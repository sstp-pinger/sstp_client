import 'dart:typed_data';

import 'ppp_config.dart';
import 'ppp_packets.dart';

/// LCP negotiator. Requests an MRU; accepts the server's auth proposal only if
/// it is CHAP/MSCHAPv2 (the one auth this milestone implements), otherwise
/// Naks proposing MSCHAPv2.
class LcpNegotiator extends ConfigNegotiator {
  bool _mruRejected = false;

  LcpNegotiator({
    required super.state,
    required super.log,
    required super.send,
    required super.inbox,
  }) : super(name: 'LCP', protocol: pppProtocolLcp);

  @override
  List<PppOption> buildRequestOptions() {
    final opts = <PppOption>[];
    if (!_mruRejected) {
      final v = Uint8List(2)
        ..[0] = (state.desiredMru >> 8) & 0xff
        ..[1] = state.desiredMru & 0xff;
      opts.add(PppOption(lcpOptionMru, v));
    }
    return opts;
  }

  @override
  ServerReview reviewServerRequest(List<PppOption> options) {
    // Reject options we don't understand at all.
    final unknown = options
        .where((o) => o.type != lcpOptionMru && o.type != lcpOptionAuth)
        .toList();
    if (unknown.isNotEmpty) {
      log.debug(name,
          'rejecting unknown LCP options: ${unknown.map((o) => o.type).toList()}');
      return ServerReview.reject(unknown);
    }

    final auth = options.where((o) => o.type == lcpOptionAuth).firstOrNull;
    final authOk = _isAcceptableAuth(auth);

    if (!authOk) {
      // Nak proposing CHAP with the MSCHAPv2 algorithm.
      final proposal = PppOption(
        lcpOptionAuth,
        Uint8List.fromList([
          (pppProtocolChap >> 8) & 0xff,
          pppProtocolChap & 0xff,
          chapAlgorithmMschapV2,
        ]),
      );
      log.debug(name, 'server auth not acceptable, proposing MSCHAPv2 via Nak');
      return ServerReview.nak([proposal]);
    }

    state.chosenAuthProtocol = pppProtocolChap;
    log.info(name, 'auth accepted: CHAP/MSCHAPv2');
    // Ack the whole request unchanged.
    return ServerReview.ack(options);
  }

  bool _isAcceptableAuth(PppOption? auth) {
    if (auth == null) return false;
    if (auth.value.length < 2) return false;
    final proto = (auth.value[0] << 8) | auth.value[1];
    if (proto == pppProtocolChap) {
      // CHAP: next byte is the algorithm; require MSCHAPv2 (0x81).
      return auth.value.length >= 3 && auth.value[2] == chapAlgorithmMschapV2;
    }
    return false;
  }

  @override
  bool onNak(List<PppOption> options) {
    for (final o in options) {
      if (o.type == lcpOptionMru && o.value.length >= 2) {
        state.currentMru = (o.value[0] << 8) | o.value[1];
        log.debug(name, 'adopting server MRU suggestion ${state.currentMru}');
      }
    }
    return true;
  }

  @override
  bool onReject(List<PppOption> options) {
    for (final o in options) {
      if (o.type == lcpOptionMru) {
        _mruRejected = true;
        log.debug(name, 'MRU option rejected; dropping it');
      }
      if (o.type == lcpOptionAuth) {
        log.error(name, 'server rejected our auth proposal');
        return false;
      }
    }
    return true;
  }
}

/// IPCP negotiator. Requests an IPv4 address (initially 0.0.0.0); the server
/// replies with a Configure-Nak carrying the real address, which we adopt and
/// re-request. That Nak is the success path, not an error.
class IpcpNegotiator extends ConfigNegotiator {
  IpcpNegotiator({
    required super.state,
    required super.log,
    required super.send,
    required super.inbox,
  }) : super(name: 'IPCP', protocol: pppProtocolIpcp);

  @override
  List<PppOption> buildRequestOptions() {
    return [PppOption(ipcpOptionIpAddress, Uint8List.fromList(state.currentIpv4))];
  }

  @override
  ServerReview reviewServerRequest(List<PppOption> options) {
    // Reject the server's DNS-server options (a client has none to offer) and
    // any unknown option. Ack whatever remains (typically the server's own IP).
    final toReject = options
        .where((o) =>
            o.type == ipcpOptionPrimaryDns ||
            o.type == ipcpOptionSecondaryDns ||
            o.type != ipcpOptionIpAddress)
        .toList();
    if (toReject.isNotEmpty) {
      return ServerReview.reject(toReject);
    }
    return ServerReview.ack(options);
  }

  @override
  bool onNak(List<PppOption> options) {
    for (final o in options) {
      if (o.type == ipcpOptionIpAddress && o.value.length == 4) {
        state.currentIpv4 = Uint8List.fromList(o.value);
        log.info(name, 'server assigned IP ${_fmtIp(o.value)}');
      } else if (o.type == ipcpOptionPrimaryDns && o.value.length == 4) {
        state.assignedDns = Uint8List.fromList(o.value);
        log.debug(name, 'server DNS ${_fmtIp(o.value)}');
      }
    }
    return true;
  }

  @override
  bool onReject(List<PppOption> options) {
    for (final o in options) {
      if (o.type == ipcpOptionIpAddress) {
        log.error(name, 'server rejected our IP address option');
        return false;
      }
    }
    return true;
  }

  static String _fmtIp(List<int> b) => b.join('.');
}

extension _FirstOrNull<E> on Iterable<E> {
  E? get firstOrNull => isEmpty ? null : first;
}

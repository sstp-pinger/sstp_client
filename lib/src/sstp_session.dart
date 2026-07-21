import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'bytes.dart';
import 'chap_auth.dart';
import 'crypto_binding.dart';
import 'frame_queue.dart';
import 'lcp_ipcp.dart';
import 'logging.dart';
import 'ppp_config.dart';
import 'ppp_packets.dart';
import 'sstp_framer.dart';
import 'sstp_packets.dart';
import 'tls_transport.dart';

/// Result of a completed Milestone-1 handshake.
class HandshakeResult {
  final String assignedIp;
  final String? dns;
  final int mru;
  HandshakeResult({required this.assignedIp, this.dns, required this.mru});
}

/// Orchestrates the full SSTP + PPP handshake through IPCP, routing inbound
/// frames from the framer to whichever negotiation stage is currently active.
class SstpSession {
  final String host;
  final int port;
  final String userName;
  final String password;
  final Logger log;
  final bool verifyCertificate;

  /// Optional Go/uTLS relay helper path. When set, TLS is performed by the
  /// helper with a browser fingerprint instead of Dart's [SecureSocket] — used
  /// to get past networks that fingerprint-block the Dart ClientHello.
  final String? relayHelperPath;
  final String tlsFingerprint;

  TlsTransport? _transport;
  SstpFramer? _framer;
  final PppState _state = PppState();

  // The active PPP consumer, keyed by protocol. Only one negotiator runs at a
  // time; unroutable protocols get a Protocol-Reject.
  final Map<int, FrameQueue<PppFrameView>> _pppRoutes = {};

  // Control-packet queue for the SSTP call setup.
  final FrameQueue<SstpControlPacket> _controlInbox = FrameQueue();

  StreamSubscription? _pppSub;
  StreamSubscription? _ctrlSub;

  int _hashProtocol = certHashProtocolSha256;
  Uint8List _serverNonce = Uint8List(32);

  SstpSession({
    required this.host,
    required this.port,
    required this.userName,
    required this.password,
    required this.log,
    this.verifyCertificate = false,
    this.relayHelperPath,
    this.tlsFingerprint = 'chrome',
  });

  Future<HandshakeResult> run() async {
    _transport = TlsTransport(
      host: host,
      port: port,
      log: log,
      verifyCertificate: verifyCertificate,
      relayHelperPath: relayHelperPath,
      fingerprint: tlsFingerprint,
    );
    await _transport!.connect();

    _framer = SstpFramer.overTransport(_transport!, log);
    _ctrlSub = _framer!.controlPackets.listen(
      _onControl,
      onError: (Object e) => _controlInbox.addError(e),
    );
    _pppSub = _framer!.pppFrames.listen(
      _onPppFrame,
      onError: (Object e) {
        for (final q in _pppRoutes.values) {
          q.addError(e);
        }
      },
    );

    try {
      await _sstpCallConnect();
      await _negotiateLcp();
      await _authenticate();
      await _sendCallConnected();
      final result = await _negotiateIpcp();
      log.stage('HANDSHAKE COMPLETE');
      return result;
    } finally {
      // Leave the socket open only long enough to have reported success; the
      // caller decides when to close.
    }
  }

  // -- routing -------------------------------------------------------------

  void _onControl(SstpControlPacket ctrl) {
    switch (ctrl.messageType) {
      case sstpMsgCallDisconnect:
        _controlInbox.addError(StateError('server sent Call-Disconnect'));
        break;
      case sstpMsgCallAbort:
        _controlInbox.addError(StateError('server sent Call-Abort'));
        break;
      default:
        _controlInbox.add(ctrl);
    }
  }

  void _onPppFrame(PppFrameView v) {
    switch (v.protocol) {
      case pppProtocolLcp:
        _handleLcpFrame(v);
        break;
      case pppProtocolChap:
        _routeOrDrop(v);
        break;
      case pppProtocolIpcp:
        _routeOrDrop(v);
        break;
      case pppProtocolIp:
      case pppProtocolIpv6:
        // Data packets: no tunneling in this milestone.
        log.trace('SESSION', 'ignoring ${pppProtocolName(v.protocol)} data');
        break;
      default:
        // Unsupported control protocol (e.g. IPv6CP): Protocol-Reject so the
        // server stops retransmitting it.
        _sendProtocolReject(v);
    }
  }

  void _handleLcpFrame(PppFrameView v) {
    // Always answer LCP echo/terminate regardless of negotiation stage.
    if (v.code == lcpCodeEchoRequest) {
      log.trace('LCP', 'replying to Echo-Request');
      _framer!.send(buildPppFrame(
        protocol: pppProtocolLcp,
        code: lcpCodeEchoReply,
        id: v.id,
        body: v.body,
      ));
      return;
    }
    if (v.code == lcpCodeEchoReply || v.code == lcpCodeDiscardRequest) {
      return;
    }
    if (v.code == lcpCodeTerminateRequest) {
      log.warn('LCP', 'server Terminate-Request; acking');
      _framer!.send(buildPppFrame(
        protocol: pppProtocolLcp,
        code: lcpCodeTerminateAck,
        id: v.id,
        body: v.body,
      ));
      return;
    }
    _routeOrDrop(v);
  }

  void _routeOrDrop(PppFrameView v) {
    final q = _pppRoutes[v.protocol];
    if (q != null) {
      q.add(v);
    } else {
      log.trace('SESSION',
          'no active consumer for ${pppProtocolName(v.protocol)} code=${v.code}');
    }
  }

  void _sendProtocolReject(PppFrameView v) {
    log.debug('LCP',
        'Protocol-Reject for ${pppProtocolName(v.protocol)} (0x${v.protocol.toRadixString(16)})');
    // Rejected-Protocol(2) + rejected information (the offending PPP payload).
    final body = BytesBuilder(copy: false)
      ..addByte((v.protocol >> 8) & 0xff)
      ..addByte(v.protocol & 0xff)
      ..addByte(v.code)
      ..addByte(v.id)
      ..add(v.body);
    _framer!.send(buildPppFrame(
      protocol: pppProtocolLcp,
      code: lcpCodeProtocolReject,
      id: _state.nextFrameId(),
      body: body.toBytes(),
    ));
  }

  FrameQueue<PppFrameView> _route(int protocol) {
    final q = FrameQueue<PppFrameView>();
    _pppRoutes[protocol] = q;
    return q;
  }

  void _unroute(int protocol) {
    _pppRoutes.remove(protocol)?.close();
  }

  // -- stages --------------------------------------------------------------

  Future<void> _sstpCallConnect() async {
    log.stage('SSTP Call-Connect');
    const interval = Duration(seconds: 10);
    const attempts = 3;

    for (var i = 0; i < attempts; i++) {
      log.debug('SSTP', 'sending Call-Connect-Request (attempt ${i + 1})');
      _framer!.send(SstpCallConnectRequest().toBytes());
      try {
        final ctrl = await _awaitControl(interval);
        if (ctrl is SstpCallConnectAck) {
          _hashProtocol = _resolveHash(ctrl.hashBitmask);
          _serverNonce = ctrl.nonce;
          log.info('SSTP',
              'Call-Connect-Ack: hash=${_hashProtocol == certHashProtocolSha256 ? "SHA-256" : "SHA-1"}, nonce=${toHex(_serverNonce).substring(0, 16)}...');
          return;
        }
        if (ctrl is SstpCallConnectNak) {
          throw StateError(
              'Call-Connect-Nak: ${ctrl.statusInfos.join(", ")}');
        }
        log.warn('SSTP',
            'unexpected control ${sstpMsgName(ctrl.messageType)} during connect');
      } on TimeoutException {
        log.warn('SSTP', 'no Call-Connect-Ack within ${interval.inSeconds}s');
      }
    }
    throw StateError('SSTP Call-Connect failed after $attempts attempts');
  }

  int _resolveHash(int bitmask) {
    // Bitmask: bit0=SHA1, bit1=SHA256. Prefer SHA-256.
    if (bitmask & certHashProtocolSha256 != 0) return certHashProtocolSha256;
    if (bitmask & certHashProtocolSha1 != 0) return certHashProtocolSha1;
    throw StateError('unknown cert hash bitmask $bitmask');
  }

  Future<void> _negotiateLcp() async {
    final inbox = _route(pppProtocolLcp);
    try {
      final lcp = LcpNegotiator(
        state: _state,
        log: log,
        send: _framer!.send,
        inbox: inbox,
      );
      await lcp.run();
      if (_state.chosenAuthProtocol != pppProtocolChap) {
        throw StateError(
            'server did not agree to MSCHAPv2 (chosen=${_state.chosenAuthProtocol})');
      }
    } finally {
      _unroute(pppProtocolLcp);
    }
  }

  Uint8List? _hlak;

  Future<void> _authenticate() async {
    final inbox = _route(pppProtocolChap);
    try {
      final auth = MsChapV2Auth(
        userName: userName,
        password: password,
        log: log,
        send: _framer!.send,
        inbox: inbox,
      );
      await auth.run();
      _hlak = auth.hlak;
    } finally {
      _unroute(pppProtocolChap);
    }
  }

  Future<void> _sendCallConnected() async {
    log.stage('SSTP Call-Connected (crypto binding)');
    final packet = CryptoBinding.build(
      hashProtocol: _hashProtocol,
      nonce: _serverNonce,
      serverCertDer: _transport!.serverCertificateDer,
      hlak: _hlak!,
    );
    _framer!.send(packet.toBytes());
    log.info('SSTP', 'Call-Connected sent with compound MAC');
  }

  Future<HandshakeResult> _negotiateIpcp() async {
    final inbox = _route(pppProtocolIpcp);
    try {
      final ipcp = IpcpNegotiator(
        state: _state,
        log: log,
        send: _framer!.send,
        inbox: inbox,
      );
      await ipcp.run();
      final ip = _state.currentIpv4.join('.');
      final dns = _state.assignedDns?.join('.');
      return HandshakeResult(assignedIp: ip, dns: dns, mru: _state.currentMru);
    } finally {
      _unroute(pppProtocolIpcp);
    }
  }

  Future<SstpControlPacket> _awaitControl(Duration timeout) =>
      _controlInbox.next(timeout);

  // -- data plane (available after run() completes IPCP) --------------------

  /// Raw IP datagrams arriving from the server over the tunnel.
  Stream<Uint8List> get inboundPackets {
    final f = _framer;
    if (f == null) throw StateError('session not connected');
    return f.ipPackets;
  }

  /// Sends a raw IP datagram to the server over the tunnel.
  void sendPacket(Uint8List ipPacket) {
    // IPv6 packets start with nibble 6; everything else is treated as IPv4.
    final protocol = (ipPacket.isNotEmpty && (ipPacket[0] >> 4) == 6)
        ? pppProtocolIpv6
        : pppProtocolIp;
    _framer!.send(buildIpDataPacket(protocol, ipPacket));
  }

  /// The resolved server address (real IP), for host-route pinning.
  InternetAddress? get serverAddress => _transport?.serverAddress;

  Future<void> close() async {
    await _pppSub?.cancel();
    await _ctrlSub?.cancel();
    await _framer?.close();
    await _transport?.close();
  }
}

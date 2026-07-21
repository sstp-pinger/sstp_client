import 'dart:async';
import 'dart:typed_data';

import 'bytes.dart';
import 'logging.dart';
import 'ppp_packets.dart';
import 'sstp_packets.dart';
import 'tls_transport.dart';

/// Reassembles the raw TLS byte stream into whole SSTP packets and dispatches
/// them: control packets to [controlPackets], PPP data frames to [pppFrames].
///
/// SSTP echo requests are answered automatically here so higher layers never
/// see them. The reassembly logic is transport-agnostic and unit-tested by
/// feeding [feed] deliberately fragmented byte runs.
class SstpFramer {
  final Logger log;
  final void Function(Uint8List bytes) _sink;

  final _controlController = StreamController<SstpControlPacket>.broadcast();
  final _pppController = StreamController<PppFrameView>.broadcast();
  // Raw inbound IP datagrams (payload of IP/IPv6 data packets). Kept separate
  // from control frames so the data plane never runs through the control-frame
  // parser, which would misread an IP header as code/id/length.
  final _ipController = StreamController<Uint8List>.broadcast();

  // Accumulates partial packets across TLS chunk boundaries.
  final BytesBuilder _buffer = BytesBuilder(copy: false);
  Uint8List _carry = Uint8List(0);

  StreamSubscription<Uint8List>? _sub;

  SstpFramer({
    required this.log,
    required void Function(Uint8List) sink,
  }) : _sink = sink;

  /// Convenience constructor that wires the framer to a [TlsTransport].
  factory SstpFramer.overTransport(TlsTransport transport, Logger log) {
    final framer = SstpFramer(log: log, sink: transport.send);
    framer._sub = transport.inboundBytes().listen(
          framer.feed,
          onError: (Object e, StackTrace st) {
            framer._controlController.addError(e, st);
            framer._pppController.addError(e, st);
          },
          onDone: framer._onDone,
        );
    return framer;
  }

  Stream<SstpControlPacket> get controlPackets => _controlController.stream;
  Stream<PppFrameView> get pppFrames => _pppController.stream;

  /// Raw inbound IP datagrams received over the tunnel (data plane).
  Stream<Uint8List> get ipPackets => _ipController.stream;

  void _onDone() {
    log.warn('FRAMER', 'inbound stream closed');
    _controlController.close();
    _pppController.close();
    _ipController.close();
  }

  /// Sends already-framed [bytes] to the server.
  void send(Uint8List bytes) => _sink(bytes);

  /// Feeds a chunk of raw inbound bytes into the reassembler. May yield zero,
  /// one, or several complete packets.
  void feed(Uint8List chunk) {
    // Combine any carry-over with the new chunk.
    if (_carry.isNotEmpty) {
      _buffer.add(_carry);
      _carry = Uint8List(0);
    }
    _buffer.add(chunk);
    var data = _buffer.toBytes();
    _buffer.clear();

    var offset = 0;
    while (true) {
      if (data.length - offset < 4) break; // need header
      // SSTP length is the 16-bit big-endian field at bytes 2..3.
      final packetLen = (data[offset + 2] << 8) | data[offset + 3];
      if (packetLen < 4) {
        log.error('FRAMER',
            'invalid packet length $packetLen at offset $offset; dropping stream');
        _controlController.addError(
            ParseException('invalid SSTP packet length $packetLen'));
        return;
      }
      if (data.length - offset < packetLen) break; // wait for full packet
      final packet =
          Uint8List.fromList(data.sublist(offset, offset + packetLen));
      offset += packetLen;
      _dispatch(packet);
    }

    // Retain the unconsumed tail for the next feed.
    if (offset < data.length) {
      _carry = Uint8List.fromList(data.sublist(offset));
    }
  }

  void _dispatch(Uint8List packet) {
    final typeWord = (packet[0] << 8) | packet[1];
    try {
      if (typeWord == sstpPacketTypeControl) {
        final ctrl = SstpControlPacket.parse(packet);
        _handleControl(ctrl);
      } else if (typeWord == sstpPacketTypeData) {
        // Peek the PPP protocol (offset 6) before parsing. IP/IPv6 data packets
        // carry a raw datagram with no control header, so deliver the payload
        // (everything after the 8-byte prefix) straight to the data plane.
        final protocol = (packet[6] << 8) | packet[7];
        if (protocol == pppProtocolIp || protocol == pppProtocolIpv6) {
          final payload = Uint8List.sublistView(packet, pppHeaderOffset);
          log.trace('FRAMER',
              'recv ${pppProtocolName(protocol)} datagram (${payload.length}B)');
          _ipController.add(Uint8List.fromList(payload));
          return;
        }
        final frame = PppFrameView.parse(packet);
        log.trace('FRAMER',
            'recv PPP ${pppProtocolName(frame.protocol)} ${pppCodeName(frame.protocol, frame.code)} id=${frame.id} (${packet.length}B)');
        _pppController.add(frame);
      } else {
        log.warn('FRAMER',
            'unknown SSTP packet type 0x${typeWord.toRadixString(16)}\n${hexDump(packet)}');
      }
    } on ParseException catch (e) {
      log.error('FRAMER', 'parse failure: $e\n${hexDump(packet)}');
    }
  }

  void _handleControl(SstpControlPacket ctrl) {
    log.debug('FRAMER', 'recv control ${sstpMsgName(ctrl.messageType)}');
    // Answer echo requests transparently.
    if (ctrl.messageType == sstpMsgEchoRequest) {
      log.trace('FRAMER', 'auto-replying to SSTP echo request');
      _sink(SstpGenericControl(sstpMsgEchoResponse, const []).toBytes());
      return;
    }
    _controlController.add(ctrl);
  }

  Future<void> close() async {
    await _sub?.cancel();
    if (!_controlController.isClosed) await _controlController.close();
    if (!_pppController.isClosed) await _pppController.close();
    if (!_ipController.isClosed) await _ipController.close();
  }
}

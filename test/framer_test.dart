import 'dart:typed_data';

import 'package:sstp_client/src/logging.dart';
import 'package:sstp_client/src/ppp_packets.dart';
import 'package:sstp_client/src/sstp_framer.dart';
import 'package:sstp_client/src/sstp_packets.dart';
import 'package:test/test.dart';

Logger silentLog() => Logger(level: LogLevel.error, sink: (_) {});

void main() {
  test('reassembles a control packet split across three chunks', () async {
    final sent = <Uint8List>[];
    final framer = SstpFramer(log: silentLog(), sink: sent.add);
    final received = <SstpControlPacket>[];
    framer.controlPackets.listen(received.add);

    // A full 48-byte Call-Connect-Ack.
    final nonce = Uint8List.fromList(List.generate(32, (i) => i));
    final ack = SstpCallConnectAck(2, nonce).toBytes();

    // Feed in awkward fragments: 3 bytes, then 20, then the rest.
    framer.feed(Uint8List.fromList(ack.sublist(0, 3)));
    framer.feed(Uint8List.fromList(ack.sublist(3, 23)));
    framer.feed(Uint8List.fromList(ack.sublist(23)));

    await Future<void>.delayed(Duration.zero);
    expect(received.length, 1);
    expect(received.first, isA<SstpCallConnectAck>());
    expect((received.first as SstpCallConnectAck).nonce, equals(nonce));
  });

  test('splits two packets delivered in one chunk', () async {
    final sent = <Uint8List>[];
    final framer = SstpFramer(log: silentLog(), sink: sent.add);
    final control = <SstpControlPacket>[];
    final ppp = <PppFrameView>[];
    framer.controlPackets.listen(control.add);
    framer.pppFrames.listen(ppp.add);

    final echoResp =
        SstpGenericControl(sstpMsgEchoResponse, const []).toBytes();
    final lcp = buildPppFrame(
      protocol: pppProtocolLcp,
      code: lcpCodeConfigureAck,
      id: 5,
      body: Uint8List.fromList([0x01, 0x04, 0x05, 0xDC]),
    );

    final combined = Uint8List.fromList([...echoResp, ...lcp]);
    framer.feed(combined);

    await Future<void>.delayed(Duration.zero);
    expect(control.length, 1); // echo response
    expect(ppp.length, 1);
    expect(ppp.first.code, lcpCodeConfigureAck);
    expect(ppp.first.id, 5);
  });

  test('auto-replies to an SSTP echo request without surfacing it', () async {
    final sent = <Uint8List>[];
    final framer = SstpFramer(log: silentLog(), sink: sent.add);
    final control = <SstpControlPacket>[];
    framer.controlPackets.listen(control.add);

    final echoReq = SstpGenericControl(sstpMsgEchoRequest, const []).toBytes();
    framer.feed(echoReq);

    await Future<void>.delayed(Duration.zero);
    // The request is answered internally and not delivered to consumers.
    expect(control, isEmpty);
    expect(sent.length, 1);
    final reply = SstpControlPacket.parse(sent.first);
    expect(reply.messageType, sstpMsgEchoResponse);
  });

  test('one byte at a time still reassembles', () async {
    final framer = SstpFramer(log: silentLog(), sink: (_) {});
    final ppp = <PppFrameView>[];
    framer.pppFrames.listen(ppp.add);

    final frame = buildPppFrame(
      protocol: pppProtocolIpcp,
      code: lcpCodeConfigureNak,
      id: 9,
      body: Uint8List.fromList([0x03, 0x06, 192, 168, 1, 50]),
    );
    for (final b in frame) {
      framer.feed(Uint8List.fromList([b]));
    }

    await Future<void>.delayed(Duration.zero);
    expect(ppp.length, 1);
    expect(ppp.first.body, equals([0x03, 0x06, 192, 168, 1, 50]));
  });
}

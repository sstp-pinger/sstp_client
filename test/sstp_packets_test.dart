import 'dart:typed_data';

import 'package:sstp_client/src/sstp_packets.dart';
import 'package:test/test.dart';

Uint8List hx(String h) {
  final clean = h.replaceAll(RegExp(r'\s'), '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

void main() {
  test('Call-Connect-Request encodes to the exact 14-byte wire form', () {
    // version+flags 0x1001 | length 0x000E | msgType 0x0001 | numAttr 0x0001
    // attr: reserved 00 | id 01 | len 0006 | protocolId 0001 (PPP)
    final expected = hx('1001 000E 0001 0001  00 01 0006 0001');
    expect(SstpCallConnectRequest().toBytes(), equals(expected));
  });

  test('Call-Connect-Ack parses hash bitmask and 32-byte nonce', () {
    final nonce = Uint8List.fromList(List.generate(32, (i) => i));
    final bytes = <int>[
      0x10, 0x01, // control
      0x00, 0x30, // length 48
      0x00, 0x02, // msgType = ACK
      0x00, 0x01, // numAttr
      0x00, 0x04, // reserved, id = crypto-binding-req
      0x00, 0x28, // attr length 40
      0x00, 0x00, 0x00, // reserved 3
      0x02, // hash bitmask = SHA256
      ...nonce,
    ];
    final pkt = SstpControlPacket.parse(Uint8List.fromList(bytes));
    expect(pkt, isA<SstpCallConnectAck>());
    final ack = pkt as SstpCallConnectAck;
    expect(ack.hashBitmask, 2);
    expect(ack.nonce, equals(nonce));
  });

  test('Call-Connect-Ack round-trips through toBytes/parse', () {
    final nonce = Uint8List.fromList(List.generate(32, (i) => 0xA0 + i % 16));
    final original = SstpCallConnectAck(1, nonce);
    final reparsed = SstpControlPacket.parse(original.toBytes());
    expect(reparsed, isA<SstpCallConnectAck>());
    expect((reparsed as SstpCallConnectAck).nonce, equals(nonce));
    expect(reparsed.hashBitmask, 1);
  });

  test('Call-Connected zeroed-MAC and signed forms differ only in MAC field',
      () {
    final nonce = Uint8List.fromList(List.filled(32, 0x11));
    final certHash = Uint8List.fromList(List.filled(32, 0x22));
    final mac = Uint8List.fromList(List.filled(32, 0x33));
    final pkt = SstpCallConnected(
      hashProtocol: certHashProtocolSha256,
      nonce: nonce,
      certHash: certHash,
      compoundMac: mac,
    );
    final zeroed = pkt.toBytesRaw(zeroMac: true);
    final signed = pkt.toBytesRaw(zeroMac: false);
    expect(zeroed.length, 112);
    expect(signed.length, 112);
    // Everything before the 32-byte MAC (last 32 bytes) is identical.
    expect(zeroed.sublist(0, 80), equals(signed.sublist(0, 80)));
    expect(zeroed.sublist(80), equals(Uint8List(32)));
    expect(signed.sublist(80), equals(mac));
  });

  test('Echo-Response is 8 bytes with correct header', () {
    final bytes = SstpGenericControl(sstpMsgEchoResponse, const []).toBytes();
    expect(bytes, equals(hx('1001 0008 0009 0000')));
  });

  test('parse rejects length mismatch', () {
    final bad = hx('1001 00FF 0009 0000'); // claims 255 but is 8
    expect(() => SstpControlPacket.parse(bad), throwsA(anything));
  });
}

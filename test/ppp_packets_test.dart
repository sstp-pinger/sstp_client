import 'dart:typed_data';

import 'package:sstp_client/src/bytes.dart';
import 'package:sstp_client/src/ppp_packets.dart';
import 'package:test/test.dart';

void main() {
  test('buildPppFrame produces correct SSTP+HDLC+PPP framing', () {
    // An LCP Configure-Request with a single MRU option (1500 = 0x05DC).
    final body = Uint8List.fromList([0x01, 0x04, 0x05, 0xDC]); // opt type1 len4
    final frame = buildPppFrame(
      protocol: pppProtocolLcp,
      code: lcpCodeConfigureRequest,
      id: 0x07,
      body: body,
    );
    // SSTP(4): 1000 | length | HDLC FF03 | proto C021 | code 01 | id 07 |
    // pppLen(4+body=8) | body
    // total = 8 (sstp+hdlc+proto) + 4 (ppp hdr) + 4 (body) = 16
    expect(frame.length, 16);
    expect(frame[0], 0x10);
    expect(frame[1], 0x00);
    expect((frame[2] << 8) | frame[3], 16); // sstp length
    expect((frame[4] << 8) | frame[5], pppHdlcHeader);
    expect((frame[6] << 8) | frame[7], pppProtocolLcp);
    expect(frame[8], lcpCodeConfigureRequest);
    expect(frame[9], 0x07);
    expect((frame[10] << 8) | frame[11], 8); // ppp length = 4 + body(4)
    expect(frame.sublist(12), equals(body));
  });

  test('PppFrameView.parse round-trips buildPppFrame', () {
    final body = Uint8List.fromList([0x03, 0x06, 0xC2, 0x23, 0x81, 0x00]);
    final frame = buildPppFrame(
      protocol: pppProtocolLcp,
      code: lcpCodeConfigureNak,
      id: 0x42,
      body: body,
    );
    final view = PppFrameView.parse(frame);
    expect(view.protocol, pppProtocolLcp);
    expect(view.code, lcpCodeConfigureNak);
    expect(view.id, 0x42);
    expect(view.body, equals(body));
  });

  test('parse rejects bad HDLC header', () {
    final frame = buildPppFrame(
      protocol: pppProtocolIpcp,
      code: 1,
      id: 1,
      body: Uint8List(0),
    );
    frame[4] = 0x00; // corrupt HDLC
    expect(() => PppFrameView.parse(frame), throwsA(isA<ParseException>()));
  });

  test('PppOption encode/decode list round-trips', () {
    final opts = [
      PppOption(lcpOptionMru, Uint8List.fromList([0x05, 0xDC])),
      PppOption(lcpOptionAuth, Uint8List.fromList([0xC2, 0x23, 0x81])),
    ];
    final encoded = PppOption.writeAll(opts);
    // MRU: 01 04 05 DC ; Auth: 03 05 C2 23 81
    expect(encoded, equals(Uint8List.fromList([
      0x01, 0x04, 0x05, 0xDC, //
      0x03, 0x05, 0xC2, 0x23, 0x81,
    ])));

    final decoded = PppOption.readAll(ByteReader(encoded), encoded.length);
    expect(decoded.length, 2);
    expect(decoded[0].type, lcpOptionMru);
    expect(decoded[0].value, equals([0x05, 0xDC]));
    expect(decoded[1].type, lcpOptionAuth);
    expect(decoded[1].value, equals([0xC2, 0x23, 0x81]));
  });

  test('IPCP address option encodes a 4-byte address', () {
    final opt = PppOption(ipcpOptionIpAddress, Uint8List.fromList([10, 0, 0, 5]));
    final w = ByteWriter();
    opt.write(w);
    expect(w.toBytes(), equals(Uint8List.fromList([0x03, 0x06, 10, 0, 0, 5])));
  });
}

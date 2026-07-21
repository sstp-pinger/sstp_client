import 'dart:typed_data';

import 'package:sstp_client/src/logging.dart';
import 'package:sstp_client/src/ppp_packets.dart';
import 'package:sstp_client/src/sstp_framer.dart';
import 'package:test/test.dart';

Logger silentLog() => Logger(level: LogLevel.error, sink: (_) {});

void main() {
  test('buildIpDataPacket wraps a raw datagram with no code/id/length', () {
    final ip = Uint8List.fromList([0x45, 0x00, 0x00, 0x1c, 0xDE, 0xAD]);
    final frame = buildIpDataPacket(pppProtocolIp, ip);
    // SSTP data (0x1000) | length | HDLC FF03 | proto 0021 | <ip...>
    expect(frame[0], 0x10);
    expect(frame[1], 0x00);
    expect((frame[2] << 8) | frame[3], 8 + ip.length);
    expect((frame[4] << 8) | frame[5], pppHdlcHeader);
    expect((frame[6] << 8) | frame[7], pppProtocolIp);
    expect(frame.sublist(8), equals(ip)); // datagram follows directly
  });

  test('IPv6 datagram uses the IPv6 protocol number', () {
    final ip = Uint8List.fromList([0x60, 0, 0, 0]);
    final frame = buildIpDataPacket(pppProtocolIpv6, ip);
    expect((frame[6] << 8) | frame[7], pppProtocolIpv6);
  });

  test('framer routes inbound IP data packets to the ipPackets stream', () async {
    final framer = SstpFramer(log: silentLog(), sink: (_) {});
    final ipPackets = <Uint8List>[];
    framer.ipPackets.listen(ipPackets.add);

    final datagram = Uint8List.fromList(
        List.generate(40, (i) => i == 0 ? 0x45 : i)); // fake IPv4 header
    framer.feed(buildIpDataPacket(pppProtocolIp, datagram));

    await Future<void>.delayed(Duration.zero);
    expect(ipPackets.length, 1);
    expect(ipPackets.first, equals(datagram));
  });

  test('a full IP datagram survives byte-at-a-time reassembly', () async {
    final framer = SstpFramer(log: silentLog(), sink: (_) {});
    final ipPackets = <Uint8List>[];
    framer.ipPackets.listen(ipPackets.add);

    final datagram = Uint8List.fromList(
        [0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x40, 0x00, 0x40, 0x01]);
    final frame = buildIpDataPacket(pppProtocolIp, datagram);
    for (final b in frame) {
      framer.feed(Uint8List.fromList([b]));
    }

    await Future<void>.delayed(Duration.zero);
    expect(ipPackets.single, equals(datagram));
  });
}

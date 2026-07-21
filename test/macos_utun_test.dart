import 'dart:typed_data';

import 'package:sstp_client/sstp_client.dart';
import 'package:sstp_client/src/macos_utun.dart'
    show afInet, afInet6, utunAddressFamily, utunPrefixLen;
import 'package:test/test.dart';

void main() {
  group('utun address-family prefix', () {
    test('IPv4 packet selects AF_INET (2)', () {
      final v4 = Uint8List.fromList([0x45, 0x00, 0x00, 0x28, 0xab, 0xcd]);
      expect(utunAddressFamily(v4), afInet);
      expect(afInet, 2);
    });

    test('IPv6 packet selects Darwin AF_INET6 (30, not Linux 10)', () {
      final v6 = Uint8List.fromList([0x60, 0x00, 0x00, 0x00, 0x00, 0x08]);
      expect(utunAddressFamily(v6), afInet6);
      // The trap: AF_INET6 is 10 on Linux but 30 on Darwin. Getting this wrong
      // makes the kernel misread every IPv6 packet.
      expect(afInet6, 30);
      expect(afInet6, isNot(10));
    });

    test('empty packet defaults to AF_INET rather than throwing', () {
      expect(utunAddressFamily(Uint8List(0)), afInet);
    });

    test('the prefix is 4 bytes', () => expect(utunPrefixLen, 4));
  });

  group('parseMacosDefaultRoute', () {
    test('extracts gateway and interface from `route -n get default`', () {
      const out = '''
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
''';
      final def = parseMacosDefaultRoute(out);
      expect(def, isNotNull);
      expect(def!.gateway, '192.168.1.1');
      expect(def.dev, 'en0');
    });

    test('returns null when there is no gateway (no default route)', () {
      const out = '''
   route to: default
destination: default
''';
      expect(parseMacosDefaultRoute(out), isNull);
    });
  });
}

import 'package:sstp_client/sstp_client.dart';
import 'package:test/test.dart';

void main() {
  group('parseWindowsDefaultRoute', () {
    test('extracts the gateway from a typical route print -4 table', () {
      // Real-world shape of Windows `route print -4` output.
      const out = '''
===========================================================================
Interface List
 12...00 15 5d 01 02 03 ......Ethernet
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.42     25
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
     192.168.1.0    255.255.255.0         On-link      192.168.1.42    281
===========================================================================
''';
      final def = parseWindowsDefaultRoute(out);
      expect(def, isNotNull);
      expect(def!.gateway, '192.168.1.1');
      expect(def.ifaceAddress, '192.168.1.42');
    });

    test('picks the first default row when several exist', () {
      const out = '''
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.0.0.1        10.0.0.5     10
          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.9    25
''';
      final def = parseWindowsDefaultRoute(out);
      expect(def!.gateway, '10.0.0.1');
    });

    test('ignores an On-link default (no real gateway) and returns null', () {
      const out = '''
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         On-link         10.0.0.5     10
''';
      expect(parseWindowsDefaultRoute(out), isNull);
    });

    test('ignores the Persistent Routes table (stale default gateway)', () {
      // Shape seen on a real Win10 host: the *active* default is via
      // 10.10.5.1, but a stale *persistent* default via 192.168.0.1 also
      // exists. Persistent rows carry a metric ("Default") where Active rows
      // carry the interface address — that is how we tell them apart. Taking
      // the first 0.0.0.0/0 match would risk pinning the server route to a
      // dead gateway.
      const out = '''
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0       10.10.5.1        10.10.5.77     55
        224.0.0.0        240.0.0.0         On-link        10.10.5.77    311
===========================================================================
Persistent Routes:
  Network Address            Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      192.168.0.1  Default
===========================================================================
''';
      final def = parseWindowsDefaultRoute(out);
      expect(def!.gateway, '10.10.5.1');
      expect(def.ifaceAddress, '10.10.5.77');
    });

    test('a Persistent-only default is not mistaken for an active one', () {
      const out = '''
Persistent Routes:
  Network Address            Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      192.168.0.1  Default
''';
      expect(parseWindowsDefaultRoute(out), isNull);
    });

    test('returns null when there is no default route', () {
      const out = '''
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
     192.168.1.0    255.255.255.0         On-link      192.168.1.42    281
''';
      expect(parseWindowsDefaultRoute(out), isNull);
    });
  });
}

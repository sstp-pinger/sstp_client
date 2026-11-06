import 'package:sstp_client/src/linux_routes.dart';
import 'package:test/test.dart';

void main() {
  group('parseGatewayRoute', () {
    test('reads ip route get for a host behind the gateway', () {
      final r = parseGatewayRoute(
          '172.16.16.67 via 172.16.25.1 dev ens18 src 172.16.25.5 uid 1000 \    cache ');
      expect(r!.gateway, '172.16.25.1');
      expect(r.dev, 'ens18');
    });

    test('an on-link host has no gateway', () {
      expect(
          parseGatewayRoute(
              '172.16.25.9 dev ens18 src 172.16.25.5 uid 1000 \    cache '),
          isNull);
    });

    test('reads the default route', () {
      final r = parseGatewayRoute(
          'default via 172.16.25.1 dev ens18 proto dhcp src 172.16.25.5 metric 100');
      expect(r!.gateway, '172.16.25.1');
    });
  });

  group('parseRouteSource', () {
    test('reads the LAN address toward the gateway', () {
      expect(
          parseRouteSource(
              '172.16.25.1 dev ens18 src 172.16.25.5 uid 1000 \\    cache '),
          '172.16.25.5');
    });

    test('null when ip prints no source', () {
      expect(parseRouteSource('unreachable 10.0.0.1'), isNull);
    });
  });
}

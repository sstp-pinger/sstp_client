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

  group('sshClientAddress', () {
    test('takes the client from SSH_CONNECTION', () {
      expect(sshClientAddress('172.16.16.67 51514 172.16.25.5 22'),
          '172.16.16.67');
    });

    test('nothing outside SSH, over IPv6 or from this host', () {
      expect(sshClientAddress(null), isNull);
      expect(sshClientAddress('fe80::1 51514 fe80::2 22'), isNull);
      expect(sshClientAddress('127.0.0.1 51514 127.0.0.1 22'), isNull);
    });
  });
}

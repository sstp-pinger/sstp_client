import 'package:sstp_client/src/linux_dns.dart';
import 'package:test/test.dart';

void main() {
  group('resolvectlSteps', () {
    test('sends every domain to the tunnel, never prompting', () {
      final steps = resolvectlSteps('sstp0');
      expect(steps, [
        ['--no-ask-password', 'dns', 'sstp0', '1.1.1.1', '8.8.8.8'],
        ['--no-ask-password', 'domain', 'sstp0', '~.'],
        ['--no-ask-password', 'default-route', 'sstp0', 'yes'],
      ]);
    });

    test('drops the flag for a resolvectl that does not know it', () {
      expect(resolvectlSteps('sstp0', noPrompt: false).first,
          ['dns', 'sstp0', '1.1.1.1', '8.8.8.8']);
      expect(resolvectlRevert('sstp0', noPrompt: false), ['revert', 'sstp0']);
    });
  });

  group('resolvectlLacksNoPrompt', () {
    test('spots systemd 255 rejecting the flag', () {
      // Ubuntu 24.04, verbatim.
      expect(
          resolvectlLacksNoPrompt(
              "resolvectl: unrecognized option '--no-ask-password'"),
          isTrue);
    });

    test('other failures are not retried', () {
      expect(
          resolvectlLacksNoPrompt(
              'Failed to set DNS configuration: Access denied'),
          isFalse);
    });
  });

  group('dnsFailureAdvice', () {
    test('a polkit refusal points at the setup script', () {
      final advice = dnsFailureAdvice(
          'Failed to set DNS configuration: Access denied');
      expect(advice, contains('setup_privilege.sh'));
      expect(advice, contains('sudo'));
    });

    test('anything else keeps the reason', () {
      final advice = dnsFailureAdvice('Link sstp0 not known');
      expect(advice, contains('Link sstp0 not known'));
      expect(advice, isNot(contains('setup_privilege.sh')));
    });
  });

  group('dnsBypassWarning', () {
    test('quiet when the stub resolver is in use', () {
      expect(dnsBypassWarning('# managed\nnameserver 127.0.0.53\nsearch lan\n'),
          isNull);
    });

    test('names the resolver that skips systemd-resolved', () {
      expect(dnsBypassWarning('nameserver 192.168.1.1\n'),
          allOf(contains('192.168.1.1'), isNot(contains('WSL'))));
    });

    test('explains the WSL forwarder', () {
      final warning = dnsBypassWarning('nameserver 10.255.255.254\nsearch lan\n');
      expect(warning, contains('WSL'));
      expect(warning, contains('generateResolvConf=false'));
    });

    test('ignores commented-out lines', () {
      expect(dnsBypassWarning('# nameserver 127.0.0.53\n'),
          contains('no nameserver'));
    });
  });
}

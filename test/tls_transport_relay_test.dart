import 'dart:io';
import 'dart:typed_data';

import 'package:sstp_client/src/logging.dart';
import 'package:sstp_client/src/tls_transport.dart';
import 'package:test/test.dart';

Logger silentLog() => Logger(level: LogLevel.error, sink: (_) {});

// Drives TlsTransport's relay engine end to end against the fake helper in
// test/support/fake_relay.dart (spawned via `dart run`), so it needs no network
// and no TLS. Verifies the pieces the relay path is responsible for: reading the
// helper's cert + real server IP, and completing the SSTP HTTP bootstrap.
void main() {
  final dart = Platform.resolvedExecutable;
  const fake = 'test/support/fake_relay.dart';

  test('relay mode surfaces the helper cert + real server IP and reaches 200',
      () async {
    final t = TlsTransport(
      host: '198.51.100.9', // never dialled directly — the helper does
      port: 1874,
      log: silentLog(),
      relayHelperPath: dart,
      relayHelperArgs: const ['run', fake],
    );

    await t.connect(timeout: const Duration(seconds: 30));

    expect(t.serverCertificateDer,
        equals(Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF])));
    expect(t.serverAddress?.address, '203.0.113.7');

    await t.close();
  }, timeout: const Timeout(Duration(seconds: 40)));

  test('relay mode propagates a helper handshake failure', () async {
    final t = TlsTransport(
      host: '198.51.100.9',
      port: 1874,
      log: silentLog(),
      relayHelperPath: dart,
      relayHelperArgs: const ['run', fake, 'error'],
    );

    await expectLater(
      t.connect(timeout: const Duration(seconds: 30)),
      throwsA(isA<StateError>()),
    );
    await t.close();
  }, timeout: const Timeout(Duration(seconds: 40)));
}

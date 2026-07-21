// A fake sstp-tls-relay for tests: speaks the relay protocol (READY line,
// preamble, JSON response) and then answers the SSTP_DUPLEX_POST with a 200 —
// no TLS, no network. Exercises TlsTransport's relay path in CI.
//
// Launched by the test via `dart run test/support/fake_relay.dart [mode]`.
//   mode (default "ok"): report a fixed cert + IP, then answer 200.
//   mode "error"       : report {"ok":false,...} so connect() must throw.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

const _certBytes = [0xDE, 0xAD, 0xBE, 0xEF];
const _remoteIp = '203.0.113.7';

Future<void> main(List<String> args) async {
  final mode = args.isNotEmpty ? args[0] : 'ok';
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  const token = 'faketoken';
  stdout.write('READY ${server.port} $token\n');
  await stdout.flush();

  final socket = await server.first;
  await server.close();

  final buf = BytesBuilder(copy: false);
  var preambleDone = false;
  var httpDone = false;

  socket.listen((chunk) async {
    buf.add(chunk);
    if (!preambleDone) {
      final b = buf.toBytes();
      final nl = b.indexOf(0x0a);
      if (nl < 0) return;
      preambleDone = true;
      // Anything after the newline would be HTTP; keep only that.
      final rest = b.sublist(nl + 1);
      buf.clear();
      buf.add(rest);

      if (mode == 'error') {
        socket.add(utf8.encode(
            '${jsonEncode({'ok': false, 'error': 'fake failure'})}\n'));
        await socket.flush();
        await socket.close();
        exit(0);
      }
      socket.add(utf8.encode('${jsonEncode({
            'ok': true,
            'certDer': base64.encode(Uint8List.fromList(_certBytes)),
            'remoteIp': _remoteIp,
          })}\n'));
      await socket.flush();
    }
    if (preambleDone && !httpDone) {
      final s = ascii.decode(buf.toBytes(), allowInvalid: true);
      if (s.contains('\r\n\r\n')) {
        httpDone = true;
        socket.add(ascii.encode('HTTP/1.1 200 OK\r\n\r\n'));
        await socket.flush();
      }
    }
  });
}

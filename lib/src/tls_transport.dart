import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'logging.dart';

/// TLS transport for SSTP.
///
/// Owns the socket carrying the TLS-protected SSTP stream, performs the
/// mandatory `SSTP_DUPLEX_POST` HTTP bootstrap that must precede any SSTP byte,
/// and exposes the server certificate (DER) plus an inbound byte stream. Host
/// and port are both caller-supplied — nothing here assumes 443.
///
/// Two TLS engines are supported behind an identical surface:
///
/// * **Direct** (default): Dart's own [SecureSocket] performs the handshake.
/// * **Relay** (when [relayHelperPath] is set): a bundled Go/uTLS helper does
///   the handshake with a browser ClientHello and pipes the plaintext SSTP
///   stream over loopback. This exists because some networks fingerprint the
///   ClientHello (JA3) and silently drop Dart's BoringSSL handshake while
///   passing a browser/OpenSSL one. The helper terminates TLS, so it hands the
///   server certificate back for the SSTP crypto-binding, and reports the real
///   server IP for host-route pinning.
class TlsTransport {
  final String host;
  final int port;
  final bool verifyCertificate;
  final Logger log;

  /// Path to the Go/uTLS relay helper. When null, the direct [SecureSocket]
  /// engine is used.
  final String? relayHelperPath;

  /// uTLS ClientHello to mimic in relay mode (e.g. `chrome`, `firefox`).
  final String fingerprint;

  /// Arguments passed to the relay helper on spawn. Empty for the real helper
  /// (it takes none); used by tests to launch a fake helper via `dart run`.
  final List<String> relayHelperArgs;

  // The SSTP correlation GUID identifies this session across the duplex POST.
  final String correlationId;

  // A plain [Socket] in relay mode, a [SecureSocket] (which is-a Socket) in
  // direct mode. Downstream code only uses the Socket surface.
  Socket? _socket;
  Uint8List? _serverCertDer;
  InternetAddress? _serverAddress;
  Process? _relayProc;

  // Bytes that arrived after the HTTP response headers but before the SSTP
  // reader started consuming (defensive; usually empty).
  final BytesBuilder _pending = BytesBuilder(copy: false);

  TlsTransport({
    required this.host,
    required this.port,
    required this.log,
    this.verifyCertificate = false,
    this.relayHelperPath,
    this.fingerprint = 'chrome',
    this.relayHelperArgs = const <String>[],
    String? correlationId,
  }) : correlationId = correlationId ?? _randomGuid();

  /// The resolved remote address of the server (available after [connect]).
  /// Used by the tunnel backend to pin a host route to the real server IP. In
  /// relay mode the socket's own peer is loopback, so the real IP reported by
  /// the helper takes precedence.
  InternetAddress? get serverAddress => _serverAddress ?? _socket?.remoteAddress;

  /// The DER-encoded server certificate, available after [connect].
  Uint8List get serverCertificateDer {
    final der = _serverCertDer;
    if (der == null) {
      throw StateError('server certificate not available before connect()');
    }
    return der;
  }

  /// Connects, performs the TLS handshake and the SSTP HTTP bootstrap.
  /// Completes when the server has returned `HTTP/1.1 200`.
  ///
  /// [timeout] bounds the TCP connect *and* the TLS handshake. The outer
  /// `.timeout` on the direct path is not redundant: `SecureSocket.connect`'s
  /// own `timeout` only covers establishing the TCP connection, so a host that
  /// accepts TCP but never completes the TLS handshake — a dead-but-listening
  /// VPN Gate node is exactly this — would otherwise hang forever.
  Future<void> connect({Duration timeout = const Duration(seconds: 20)}) async {
    if (relayHelperPath != null) {
      await _startRelay(timeout);
    } else {
      await _connectDirect(timeout);
    }
    await _bootstrap();
  }

  Future<void> _connectDirect(Duration timeout) async {
    log.info('TLS', 'connecting to $host:$port (verifyCert=$verifyCertificate)');
    final socket = await SecureSocket.connect(
      host,
      port,
      timeout: timeout,
      onBadCertificate: (X509Certificate cert) {
        if (verifyCertificate) {
          log.error('TLS', 'certificate rejected for $host: ${cert.subject}');
          return false;
        }
        log.warn('TLS',
            'accepting UNVERIFIED server certificate (subject=${cert.subject}, issuer=${cert.issuer})');
        return true;
      },
    ).timeout(timeout, onTimeout: () {
      log.error('TLS', 'handshake to $host:$port timed out after '
          '${timeout.inSeconds}s (server accepted TCP but never completed TLS)');
      throw TimeoutException(
          'TLS handshake to $host:$port timed out', timeout);
    });
    _socket = socket;
    _serverAddress = socket.remoteAddress;

    final cert = socket.peerCertificate;
    if (cert == null) {
      throw StateError('no peer certificate presented by $host:$port');
    }
    _serverCertDer = Uint8List.fromList(cert.der);
    log.info('TLS',
        'handshake ok, cipher negotiated, cert subject=${cert.subject}');
    log.debug('TLS', 'server cert DER length=${_serverCertDer!.length}');
  }

  /// Spawns the relay helper, reads its `READY <port> <token>` line, connects to
  /// its loopback port and sends the connect preamble. The certificate and real
  /// server IP arrive in the helper's response, read during [_bootstrap].
  Future<void> _startRelay(Duration timeout) async {
    final path = relayHelperPath!;
    log.info('TLS',
        'connecting via uTLS relay (fingerprint=$fingerprint) to $host:$port');
    final proc = await Process.start(path, relayHelperArgs);
    _relayProc = proc;

    // Surface the helper's diagnostics; the single most useful signal when a
    // relay connect fails is invisible otherwise.
    proc.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) => log.debug('RELAY', line), onError: (_) {});

    // First stdout line: "READY <port> <token>".
    final readyLine = await _firstStdoutLine(proc).timeout(timeout,
        onTimeout: () {
      proc.kill();
      throw TimeoutException('relay did not become READY', timeout);
    });
    final parts = readyLine.trim().split(RegExp(r'\s+'));
    if (parts.length != 3 || parts[0] != 'READY') {
      proc.kill();
      throw StateError('unexpected relay handshake line: "$readyLine"');
    }
    final relayPort = int.parse(parts[1]);
    final token = parts[2];

    final socket = await Socket.connect(
        InternetAddress.loopbackIPv4, relayPort,
        timeout: timeout);
    _socket = socket;

    final preamble = jsonEncode({
      'token': token,
      'host': host,
      'port': port,
      'fingerprint': fingerprint,
    });
    socket.add(utf8.encode('$preamble\n'));
    await socket.flush();
  }

  Future<String> _firstStdoutLine(Process proc) {
    final completer = Completer<String>();
    final buf = StringBuffer();
    late StreamSubscription<String> sub;
    sub = proc.stdout.transform(utf8.decoder).listen((data) {
      buf.write(data);
      final s = buf.toString();
      final nl = s.indexOf('\n');
      if (nl >= 0 && !completer.isCompleted) {
        completer.complete(s.substring(0, nl));
        sub.cancel();
      }
    }, onError: (Object e, StackTrace st) {
      if (!completer.isCompleted) completer.completeError(e, st);
    }, onDone: () {
      if (!completer.isCompleted) {
        completer.completeError(StateError('relay exited before READY'));
      }
    });
    return completer.future;
  }

  // Bootstrap phases over the single socket subscription.
  static const _phaseRelayResp = 0; // relay mode only: read the cert response
  static const _phaseHttp = 1; // read the SSTP_DUPLEX_POST HTTP headers

  /// Drives the post-connect handshake over one subscription: in relay mode it
  /// first reads the helper's JSON response (cert + real IP) and only then sends
  /// the `SSTP_DUPLEX_POST`; in direct mode the POST is already on the wire. In
  /// both cases it completes when the server returns `HTTP/1.1 200`.
  Future<void> _bootstrap() async {
    final socket = _socket!;
    final completer = Completer<void>();
    final relayBuf = BytesBuilder(copy: false);
    final headerBytes = BytesBuilder(copy: false);
    var phase = relayHelperPath != null ? _phaseRelayResp : _phaseHttp;
    var headerDone = false;

    // Direct mode: the POST can go out immediately. Relay mode waits for the
    // certificate response before sending it.
    if (phase == _phaseHttp) _sendDuplexPost(socket);

    late StreamSubscription<Uint8List> sub;
    sub = socket.listen(
      (chunk) {
        Uint8List data = chunk;

        if (phase == _phaseRelayResp) {
          relayBuf.add(data);
          final buf = relayBuf.toBytes();
          final nl = buf.indexOf(0x0a);
          if (nl < 0) return; // response line not complete yet
          try {
            _applyRelayResponse(utf8.decode(buf.sublist(0, nl)));
          } catch (e, st) {
            if (!completer.isCompleted) completer.completeError(e, st);
            sub.cancel();
            return;
          }
          _sendDuplexPost(socket); // cert in hand — now start SSTP
          phase = _phaseHttp;
          data = Uint8List.fromList(buf.sublist(nl + 1));
          if (data.isEmpty) return;
        }

        // _phaseHttp
        if (headerDone) {
          _pending.add(data);
          return;
        }
        headerBytes.add(data);
        final buf = headerBytes.toBytes();
        final idx = _indexOfCrlfCrlf(buf);
        if (idx >= 0) {
          headerDone = true;
          final headerStr = ascii.decode(buf.sublist(0, idx));
          final leftover = buf.sublist(idx + 4);
          if (leftover.isNotEmpty) _pending.add(leftover);
          sub.pause();
          _finishBootstrap(headerStr, completer);
        }
      },
      onError: (Object e, StackTrace st) {
        if (!completer.isCompleted) completer.completeError(e, st);
      },
      onDone: () {
        if (!completer.isCompleted) {
          completer.completeError(
              StateError('connection closed during HTTP bootstrap'));
        }
      },
      cancelOnError: true,
    );

    await completer.future.timeout(const Duration(seconds: 15));
    // Hand the (paused) subscription off to the framer via inboundBytes().
    _adopted = sub;
  }

  /// Parses the relay helper's one-line JSON response and records the server
  /// certificate (for the SSTP crypto-binding) and real server IP (for routing).
  void _applyRelayResponse(String line) {
    final Map<String, dynamic> resp;
    try {
      resp = jsonDecode(line) as Map<String, dynamic>;
    } catch (_) {
      throw StateError('malformed relay response: "$line"');
    }
    if (resp['ok'] != true) {
      throw StateError('relay TLS handshake failed: ${resp['error'] ?? 'unknown'}');
    }
    final certB64 = resp['certDer'] as String?;
    if (certB64 == null || certB64.isEmpty) {
      throw StateError('relay returned no certificate');
    }
    _serverCertDer = base64.decode(certB64);
    final remoteIp = resp['remoteIp'] as String?;
    if (remoteIp != null && remoteIp.isNotEmpty) {
      try {
        _serverAddress = InternetAddress(remoteIp);
      } catch (_) {
        // Non-fatal: routing falls back to the caller-supplied host.
      }
    }
    log.info('TLS',
        'relay handshake ok, remoteIp=$remoteIp, cert DER length=${_serverCertDer!.length}');
  }

  /// Sends the `SSTP_DUPLEX_POST` request. The Content-Length of 2^64-1 is the
  /// MS-SSTP sentinel for an unbounded duplex stream, not a real length.
  void _sendDuplexPost(Socket socket) {
    final request = [
      'SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1',
      'Host: $host',
      'SSTPCORRELATIONID: {$correlationId}',
      'Content-Length: 18446744073709551615',
      '',
      '',
    ].join('\r\n');
    log.debug('HTTP', 'sending SSTP_DUPLEX_POST (correlationId=$correlationId)');
    socket.add(ascii.encode(request));
    socket.flush();
  }

  void _finishBootstrap(String headerStr, Completer<void> completer) {
    final statusLine = headerStr.split('\r\n').first;
    log.debug('HTTP', 'response: $statusLine');
    if (!statusLine.contains('200')) {
      completer.completeError(
          StateError('SSTP HTTP bootstrap failed: "$statusLine"'));
      return;
    }
    log.info('HTTP', 'SSTP_DUPLEX_POST accepted (200)');
    completer.complete();
  }

  StreamSubscription<Uint8List>? _adopted;

  /// Returns a stream of inbound TLS-decrypted bytes for the framer to consume.
  /// Any bytes already buffered during the HTTP bootstrap are delivered first.
  Stream<Uint8List> inboundBytes() {
    final socket = _socket;
    final sub = _adopted;
    if (socket == null || sub == null) {
      throw StateError('inboundBytes() called before connect()');
    }
    final controller = StreamController<Uint8List>();

    final leftover = _pending.toBytes();
    if (leftover.isNotEmpty) {
      log.trace('TLS', '${leftover.length} bytes buffered from bootstrap');
      controller.add(leftover);
    }

    sub.onData((chunk) => controller.add(chunk));
    sub.onError((Object e, StackTrace st) => controller.addError(e, st));
    sub.onDone(() => controller.close());
    sub.resume();

    controller.onCancel = () => sub.cancel();
    return controller.stream;
  }

  /// Sends raw bytes (a fully framed SSTP packet) to the server.
  void send(Uint8List bytes) {
    final socket = _socket;
    if (socket == null) throw StateError('send() before connect()');
    socket.add(bytes);
  }

  Future<void> flush() => _socket?.flush() ?? Future.value();

  Future<void> close() async {
    try {
      await _adopted?.cancel();
      await _socket?.close();
    } catch (_) {
      // best effort
    }
    _socket?.destroy();
    _relayProc?.kill();
  }

  static int _indexOfCrlfCrlf(Uint8List buf) {
    for (var i = 0; i + 3 < buf.length; i++) {
      if (buf[i] == 0x0d &&
          buf[i + 1] == 0x0a &&
          buf[i + 2] == 0x0d &&
          buf[i + 3] == 0x0a) {
        return i;
      }
    }
    return -1;
  }

  static String _randomGuid() {
    final r = _rng;
    String h(int n) {
      final sb = StringBuffer();
      for (var i = 0; i < n; i++) {
        sb.write(r.nextInt(16).toRadixString(16));
      }
      return sb.toString();
    }

    return '${h(8)}-${h(4)}-4${h(3)}-${(8 + r.nextInt(4)).toRadixString(16)}${h(3)}-${h(12)}'
        .toUpperCase();
  }
}

// The correlation GUID is an identifier, not a secret; a secure RNG is used
// anyway since one is readily available.
final Random _rng = Random.secure();

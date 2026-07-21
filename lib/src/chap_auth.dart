import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'bytes.dart';
import 'frame_queue.dart';
import 'logging.dart';
import 'mschapv2.dart';
import 'ppp_packets.dart';

/// Drives the CHAP/MSCHAPv2 handshake:
///   server Challenge -> our Response -> server Success/Failure.
///
/// On success it verifies the server's authenticator string and derives the
/// 32-byte HLAK used later by the SSTP crypto binding.
class MsChapV2Auth {
  final String userName;
  final String password;
  final Logger log;
  final void Function(Uint8List framed) send;
  final FrameQueue<PppFrameView> inbox;

  static const Duration timeout = Duration(seconds: 30);

  final _rng = Random.secure();

  Uint8List? hlak;

  MsChapV2Auth({
    required this.userName,
    required this.password,
    required this.log,
    required this.send,
    required this.inbox,
  });

  Future<void> run() async {
    log.stage('MSCHAPv2 authentication');

    // 1. Wait for the server Challenge.
    final challenge = await _waitFor(chapCodeChallenge);
    final serverChallenge = _parseValue(challenge.body);
    if (serverChallenge.length != 16) {
      throw StateError(
          'unexpected CHAP challenge value length ${serverChallenge.length}');
    }
    log.debug('MSCHAPv2', 'server challenge received (id=${challenge.id})');

    // 2. Build and send the Response.
    final peerChallenge = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      peerChallenge[i] = _rng.nextInt(256);
    }
    final nt = MsChapV2.buildNtResponse(
      authChallenge: serverChallenge,
      peerChallenge: peerChallenge,
      userName: userName,
      password: password,
    );

    // Response value (49 bytes): peerChallenge(16) reserved(8, zero)
    // ntResponse(24) flags(1).
    final value = Uint8List(49);
    value.setRange(0, 16, peerChallenge);
    // bytes 16..24 stay zero (reserved)
    value.setRange(24, 48, nt.ntResponse);
    value[48] = 0;

    final nameBytes = ascii.encode(userName);
    final body = BytesBuilder(copy: false)
      ..addByte(value.length)
      ..add(value)
      ..add(nameBytes);
    final framed = buildPppFrame(
      protocol: pppProtocolChap,
      code: chapCodeResponse,
      id: challenge.id, // response echoes the challenge id
      body: body.toBytes(),
    );
    log.debug('MSCHAPv2', 'sending response (id=${challenge.id})');
    send(framed);

    // 3. Await Success or Failure.
    final result = await _waitForResult(challenge.id);
    if (result.code == chapCodeFailure) {
      final msg = ascii.decode(result.body, allowInvalid: true);
      throw StateError('MSCHAPv2 authentication failed: $msg');
    }

    // Success: verify the server authenticator (S=...).
    final message = ascii.decode(result.body, allowInvalid: true);
    final expected = MsChapV2.authenticatorResponse(
      password: password,
      ntResponse: nt.ntResponse,
      peerChallenge: peerChallenge,
      authChallenge: serverChallenge,
      userName: userName,
    );
    if (!message.contains(expected)) {
      throw StateError(
          'MSCHAPv2 server authenticator mismatch (got "$message", want "$expected")');
    }
    log.info('MSCHAPv2', 'server authenticator verified');

    hlak = MsChapV2.deriveHlak(password: password, ntResponse: nt.ntResponse);
    log.info('MSCHAPv2', 'authentication successful, HLAK derived');
  }

  /// Reads value-size(1) then value(value-size) from a CHAP value/name body.
  Uint8List _parseValue(Uint8List body) {
    final r = ByteReader(body);
    final size = r.readByte();
    return r.readBytes(size);
  }

  Future<PppFrameView> _waitFor(int code) async {
    while (true) {
      final v = await inbox.next(timeout);
      if (v.protocol != pppProtocolChap) continue;
      if (v.code == code) return v;
      log.trace('MSCHAPv2', 'ignoring CHAP code ${v.code} while awaiting $code');
    }
  }

  Future<PppFrameView> _waitForResult(int challengeId) async {
    while (true) {
      final v = await inbox.next(timeout);
      if (v.protocol != pppProtocolChap) continue;
      if (v.code == chapCodeSuccess || v.code == chapCodeFailure) {
        if (v.id != challengeId) {
          log.trace('MSCHAPv2', 'result id ${v.id} != $challengeId, ignoring');
          continue;
        }
        return v;
      }
    }
  }
}

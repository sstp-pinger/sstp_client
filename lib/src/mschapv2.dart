import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/digests/md4.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/block/desede_engine.dart';
import 'package:pointycastle/api.dart';

import 'bytes.dart';

// MS-CHAPv2 (RFC 2759) and MS-MPPE (RFC 3079) magic constants. These are
// literal ASCII strings in the specs; encoding them here avoids hand-copied
// hex transcription errors.
final Uint8List _magicServerSigning =
    ascii.encode('Magic server to client signing constant');
final Uint8List _magicPad =
    ascii.encode('Pad to make it do more than one iteration');
final Uint8List _magicMppeMasterKey =
    ascii.encode('This is the MPPE Master Key');
final Uint8List _magicSendKey = ascii.encode('On the client side, this is the '
    'send key; on the server side, it is the receive key.');
final Uint8List _magicReceiveKey = ascii.encode('On the client side, this is '
    'the receive key; on the server side, it is the send key.');

/// Pure MSCHAPv2 (RFC 2759) primitives with no I/O. Every method is static and
/// deterministic given its inputs, so each step is unit-testable against the
/// RFC 2759 test vectors.
class MsChapV2 {
  /// NtPasswordHash = MD4(UTF-16LE(password)).
  static Uint8List ntPasswordHash(String password) => _md4(_utf16le(password));

  /// NtPasswordHashHash = MD4(NtPasswordHash).
  static Uint8List hashNtPasswordHash(Uint8List passwordHash) =>
      _md4(passwordHash);

  /// ChallengeHash (RFC 2759 sec 8.2):
  /// SHA1(peerChallenge | authChallenge | userName)[0..8].
  static Uint8List challengeHash(
      Uint8List peerChallenge, Uint8List authChallenge, String userName) {
    final d = SHA1Digest();
    d.update(peerChallenge, 0, peerChallenge.length);
    d.update(authChallenge, 0, authChallenge.length);
    final user = ascii.encode(userName);
    d.update(user, 0, user.length);
    final out = Uint8List(20);
    d.doFinal(out, 0);
    return Uint8List.fromList(out.sublist(0, 8));
  }

  /// ChallengeResponse (RFC 2759 sec 8.5): DES-encrypt the 8-byte challenge
  /// under three keys derived from the zero-padded 21-byte password hash.
  static Uint8List challengeResponse(
      Uint8List challenge8, Uint8List passwordHash16) {
    final zpwHash = Uint8List(21)..setRange(0, 16, passwordHash16);
    final response = Uint8List(24);
    for (var i = 0; i < 3; i++) {
      final key7 = Uint8List.fromList(zpwHash.sublist(i * 7, i * 7 + 7));
      final desKey = _addParity(key7);
      final block = _desEncrypt(desKey, challenge8);
      response.setRange(i * 8, i * 8 + 8, block);
    }
    return response;
  }

  /// Builds the 24-byte NT-Response plus the intermediates callers reuse.
  static NtResponse buildNtResponse({
    required Uint8List authChallenge,
    required Uint8List peerChallenge,
    required String userName,
    required String password,
  }) {
    final chalHash = challengeHash(peerChallenge, authChallenge, userName);
    final pwHash = ntPasswordHash(password);
    final ntResponse = challengeResponse(chalHash, pwHash);
    return NtResponse(ntResponse, chalHash, pwHash);
  }

  /// GenerateAuthenticatorResponse (RFC 2759 sec 8.7). Returns the ASCII
  /// "S=<40 uppercase hex>" string the server sends on success.
  static String authenticatorResponse({
    required String password,
    required Uint8List ntResponse,
    required Uint8List peerChallenge,
    required Uint8List authChallenge,
    required String userName,
  }) {
    final pwHash = ntPasswordHash(password);
    final pwHashHash = hashNtPasswordHash(pwHash);

    final d = SHA1Digest();
    d.update(pwHashHash, 0, pwHashHash.length);
    d.update(ntResponse, 0, ntResponse.length);
    d.update(_magicServerSigning, 0, _magicServerSigning.length);
    final digest0 = Uint8List(20);
    d.doFinal(digest0, 0);

    final chalHash = challengeHash(peerChallenge, authChallenge, userName);

    d.reset();
    d.update(digest0, 0, digest0.length);
    d.update(chalHash, 0, chalHash.length);
    d.update(_magicPad, 0, _magicPad.length);
    final digest1 = Uint8List(20);
    d.doFinal(digest1, 0);

    return 'S=${toHex(digest1).toUpperCase()}';
  }

  /// Derives the 32-byte HLAK (higher-layer authentication key) the SSTP
  /// crypto binding is keyed with: MPPE send key (16) || receive key (16),
  /// per RFC 3079 GetMasterKey + GetAsymmetricStartKey.
  static Uint8List deriveHlak({
    required String password,
    required Uint8List ntResponse,
  }) {
    final pwHash = ntPasswordHash(password);
    final pwHashHash = hashNtPasswordHash(pwHash);

    // GetMasterKey: SHA1(pwHashHash | ntResponse | magic)[0..16].
    final dm = SHA1Digest();
    dm.update(pwHashHash, 0, pwHashHash.length);
    dm.update(ntResponse, 0, ntResponse.length);
    dm.update(_magicMppeMasterKey, 0, _magicMppeMasterKey.length);
    final masterDigest = Uint8List(20);
    dm.doFinal(masterDigest, 0);
    final masterKey = Uint8List.fromList(masterDigest.sublist(0, 16));

    final pad1 = Uint8List(40); // 0x00 * 40
    final pad2 = Uint8List(40)..fillRange(0, 40, 0xF2);

    Uint8List asymmetricKey(Uint8List sessionMagic) {
      final d = SHA1Digest();
      d.update(masterKey, 0, masterKey.length);
      d.update(pad1, 0, pad1.length);
      d.update(sessionMagic, 0, sessionMagic.length);
      d.update(pad2, 0, pad2.length);
      final out = Uint8List(20);
      d.doFinal(out, 0);
      return Uint8List.fromList(out.sublist(0, 16));
    }

    final sendKey = asymmetricKey(_magicSendKey);
    final recvKey = asymmetricKey(_magicReceiveKey);

    final hlak = Uint8List(32);
    hlak.setRange(0, 16, sendKey);
    hlak.setRange(16, 32, recvKey);
    return hlak;
  }

  // -- primitives ----------------------------------------------------------

  static Uint8List _md4(Uint8List input) {
    final d = MD4Digest();
    d.update(input, 0, input.length);
    final out = Uint8List(16);
    d.doFinal(out, 0);
    return out;
  }

  /// Expands a 7-byte key into an 8-byte DES key by taking successive 7-bit
  /// groups (most-significant first) and appending an odd-parity bit. DES
  /// ignores the parity bit, so it does not affect ciphertext, but we set it
  /// to match the reference implementation.
  static Uint8List _addParity(Uint8List key7) {
    var acc = 0;
    for (final b in key7) {
      acc = (acc << 8) | b;
    }
    final out = Uint8List(8);
    for (var i = 0; i < 8; i++) {
      final shift = 56 - 7 * (i + 1);
      final sevenBits = (acc >> shift) & 0x7f;
      out[i] = ((sevenBits << 1) | _oddParityBit(sevenBits)) & 0xff;
    }
    return out;
  }

  static int _oddParityBit(int sevenBits) {
    var count = 0;
    var v = sevenBits;
    for (var i = 0; i < 7; i++) {
      count += v & 1;
      v >>= 1;
    }
    return (count % 2 == 0) ? 1 : 0;
  }

  static Uint8List _desEncrypt(Uint8List key8, Uint8List block8) {
    // pointycastle ships only triple-DES; single-DES is 3DES (E-D-E) with all
    // three 8-byte subkeys equal, so replicate key8 three times.
    final key24 = Uint8List(24)
      ..setRange(0, 8, key8)
      ..setRange(8, 16, key8)
      ..setRange(16, 24, key8);
    final des = DESedeEngine()..init(true, KeyParameter(key24));
    final out = Uint8List(8);
    des.processBlock(block8, 0, out, 0);
    return out;
  }

  static Uint8List _utf16le(String s) {
    final units = s.codeUnits;
    final out = Uint8List(units.length * 2);
    for (var i = 0; i < units.length; i++) {
      out[i * 2] = units[i] & 0xff;
      out[i * 2 + 1] = (units[i] >> 8) & 0xff;
    }
    return out;
  }
}

/// Result of building an NT-Response: the response plus intermediates callers
/// reuse (challenge hash, password hash).
class NtResponse {
  final Uint8List ntResponse; // 24 bytes
  final Uint8List challengeHash; // 8 bytes
  final Uint8List passwordHash; // 16 bytes
  NtResponse(this.ntResponse, this.challengeHash, this.passwordHash);
}

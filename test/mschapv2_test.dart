import 'dart:typed_data';

import 'package:sstp_client/src/bytes.dart';
import 'package:sstp_client/src/mschapv2.dart';
import 'package:test/test.dart';

Uint8List hx(String h) {
  final clean = h.replaceAll(' ', '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

void main() {
  // Test vectors from RFC 2759 section 9.2.
  const userName = 'User';
  const password = 'clientPass';
  final authChallenge = hx('5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28');
  final peerChallenge = hx('21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E');
  final expectedChallengeHash = hx('D0 2E 43 86 BC E9 12 26');
  final expectedPasswordHash = hx('44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE');
  final expectedPasswordHashHash = hx('41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F');
  final expectedNtResponse = hx('82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 '
      '42 33 11 4A 3D 85 D6 DF');
  const expectedAuthenticator = 'S=407A5589115FD0D6209F510FE9C04566932CDA56';

  test('NtPasswordHash matches RFC 2759', () {
    expect(MsChapV2.ntPasswordHash(password), equals(expectedPasswordHash));
  });

  test('NtPasswordHashHash matches RFC 2759', () {
    final h = MsChapV2.ntPasswordHash(password);
    expect(MsChapV2.hashNtPasswordHash(h), equals(expectedPasswordHashHash));
  });

  test('ChallengeHash matches RFC 2759', () {
    expect(MsChapV2.challengeHash(peerChallenge, authChallenge, userName),
        equals(expectedChallengeHash));
  });

  test('NtResponse (ChallengeResponse) matches RFC 2759', () {
    final r = MsChapV2.buildNtResponse(
      authChallenge: authChallenge,
      peerChallenge: peerChallenge,
      userName: userName,
      password: password,
    );
    expect(r.ntResponse, equals(expectedNtResponse));
    expect(r.challengeHash, equals(expectedChallengeHash));
  });

  test('AuthenticatorResponse matches RFC 2759', () {
    final auth = MsChapV2.authenticatorResponse(
      password: password,
      ntResponse: expectedNtResponse,
      peerChallenge: peerChallenge,
      authChallenge: authChallenge,
      userName: userName,
    );
    expect(auth, equals(expectedAuthenticator));
  });

  test('HLAK is 32 bytes and deterministic', () {
    final h1 = MsChapV2.deriveHlak(password: password, ntResponse: expectedNtResponse);
    final h2 = MsChapV2.deriveHlak(password: password, ntResponse: expectedNtResponse);
    expect(h1.length, 32);
    expect(h1, equals(h2));
  });

  test('toHex round-trips', () {
    expect(toHex(hx('DEADBEEF')), 'deadbeef');
  });
}

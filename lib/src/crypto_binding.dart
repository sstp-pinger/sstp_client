import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/api.dart';

import 'sstp_packets.dart';

/// Builds the SSTP Call-Connected crypto binding (MS-SSTP 3.2.5.2.2).
///
/// The compound MAC binds the PPP authentication (via HLAK) to the TLS channel
/// (via the server certificate hash) and the server nonce from Call-Connect-Ack.
class CryptoBinding {
  static const String _cmkSeed = 'SSTP inner method derived CMK';

  /// Constructs the fully-signed Call-Connected packet.
  ///
  /// [hashProtocol] is [certHashProtocolSha1] or [certHashProtocolSha256] as
  /// dictated by the server's Call-Connect-Ack bitmask. [nonce] is the 32-byte
  /// server nonce; [serverCertDer] is the DER-encoded server certificate;
  /// [hlak] is the 32-byte key derived from MSCHAPv2.
  static SstpCallConnected build({
    required int hashProtocol,
    required Uint8List nonce,
    required Uint8List serverCertDer,
    required Uint8List hlak,
  }) {
    final useSha256 = hashProtocol == certHashProtocolSha256;
    final macLen = useSha256 ? 32 : 20;

    // Certificate hash over the DER encoding.
    final certHashFull =
        useSha256 ? _sha256(serverCertDer) : _sha1(serverCertDer);
    final certHash = Uint8List(32)..setRange(0, certHashFull.length, certHashFull);

    // Assemble the packet with a zeroed MAC; that is exactly the input the
    // CMAC is computed over.
    final packet = SstpCallConnected(
      hashProtocol: hashProtocol,
      nonce: Uint8List.fromList(nonce),
      certHash: certHash,
    );
    final macInput = packet.toBytesRaw(zeroMac: true);

    // CMK = HMAC(HLAK, seed | macLen(2, little-endian) | 0x01).
    final cmkInput = BytesBuilder(copy: false)
      ..add(ascii.encode(_cmkSeed))
      ..addByte(macLen & 0xff)
      ..addByte((macLen >> 8) & 0xff)
      ..addByte(0x01);
    final cmk = _hmac(useSha256, hlak, cmkInput.toBytes());

    // CMAC = HMAC(CMK, packet-with-zeroed-MAC).
    final cmac = _hmac(useSha256, cmk, macInput);

    final compoundMac = Uint8List(32)..setRange(0, cmac.length, cmac);
    packet.compoundMac = compoundMac;
    return packet;
  }

  static Uint8List _hmac(bool sha256, Uint8List key, Uint8List data) {
    final digest = sha256 ? SHA256Digest() : SHA1Digest();
    final mac = HMac(digest, digest.byteLength)..init(KeyParameter(key));
    return mac.process(data);
  }

  static Uint8List _sha256(Uint8List data) => SHA256Digest().process(data);
  static Uint8List _sha1(Uint8List data) => SHA1Digest().process(data);
}

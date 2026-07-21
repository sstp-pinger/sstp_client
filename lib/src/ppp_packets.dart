import 'dart:typed_data';

import 'bytes.dart';
import 'sstp_packets.dart';

// PPP-in-SSTP framing. A data packet is:
//   SSTP header(4) | HDLC 0xFF03 (2) | PPP protocol(2) | PPP body
// The PPP length field inside a control frame counts from the code byte and is
// therefore (sstpLength - 8).
const int pppHdlcHeader = 0xFF03;

const int pppProtocolLcp = 0xC021;
const int pppProtocolPap = 0xC023;
const int pppProtocolChap = 0xC223;
const int pppProtocolEap = 0xC227;
const int pppProtocolIpcp = 0x8021;
const int pppProtocolIpv6cp = 0x8057;
const int pppProtocolIp = 0x0021;
const int pppProtocolIpv6 = 0x0057;

// Configuration codes shared by LCP and IPCP (RFC 1661).
const int lcpCodeConfigureRequest = 1;
const int lcpCodeConfigureAck = 2;
const int lcpCodeConfigureNak = 3;
const int lcpCodeConfigureReject = 4;
const int lcpCodeTerminateRequest = 5;
const int lcpCodeTerminateAck = 6;
const int lcpCodeCodeReject = 7;
const int lcpCodeProtocolReject = 8;
const int lcpCodeEchoRequest = 9;
const int lcpCodeEchoReply = 10;
const int lcpCodeDiscardRequest = 11;

// CHAP codes (RFC 1994).
const int chapCodeChallenge = 1;
const int chapCodeResponse = 2;
const int chapCodeSuccess = 3;
const int chapCodeFailure = 4;

/// Offset from the start of an SSTP data packet to the PPP code byte:
/// SSTP(4) + HDLC(2) + protocol(2).
const int pppHeaderOffset = 8;

String pppProtocolName(int p) {
  switch (p) {
    case pppProtocolLcp:
      return 'LCP';
    case pppProtocolPap:
      return 'PAP';
    case pppProtocolChap:
      return 'CHAP';
    case pppProtocolEap:
      return 'EAP';
    case pppProtocolIpcp:
      return 'IPCP';
    case pppProtocolIpv6cp:
      return 'IPv6CP';
    case pppProtocolIp:
      return 'IP';
    case pppProtocolIpv6:
      return 'IPv6';
    default:
      return 'proto-0x${p.toRadixString(16)}';
  }
}

/// Names a PPP frame's code appropriately for its protocol (CHAP uses a
/// different code space from the LCP/IPCP configuration codes).
String pppCodeName(int protocol, int code) {
  if (protocol == pppProtocolChap) {
    switch (code) {
      case chapCodeChallenge:
        return 'Challenge';
      case chapCodeResponse:
        return 'Response';
      case chapCodeSuccess:
        return 'Success';
      case chapCodeFailure:
        return 'Failure';
      default:
        return 'chap-code-$code';
    }
  }
  return configCodeName(code);
}

String configCodeName(int code) {
  switch (code) {
    case lcpCodeConfigureRequest:
      return 'Configure-Request';
    case lcpCodeConfigureAck:
      return 'Configure-Ack';
    case lcpCodeConfigureNak:
      return 'Configure-Nak';
    case lcpCodeConfigureReject:
      return 'Configure-Reject';
    case lcpCodeTerminateRequest:
      return 'Terminate-Request';
    case lcpCodeTerminateAck:
      return 'Terminate-Ack';
    case lcpCodeCodeReject:
      return 'Code-Reject';
    case lcpCodeProtocolReject:
      return 'Protocol-Reject';
    case lcpCodeEchoRequest:
      return 'Echo-Request';
    case lcpCodeEchoReply:
      return 'Echo-Reply';
    default:
      return 'code-$code';
  }
}

/// The raw view of a received PPP frame: protocol, code, id, and the body that
/// follows the 4-byte PPP header (code, id, length). Higher layers decode the
/// body per protocol.
class PppFrameView {
  final int protocol;
  final int code;
  final int id;
  final Uint8List body; // bytes after the 4-byte PPP header

  PppFrameView(this.protocol, this.code, this.id, this.body);

  /// Parses a full SSTP data packet [data] into a PPP frame view.
  static PppFrameView parse(Uint8List data) {
    final r = ByteReader(data);
    final firstWord = r.readUint16();
    if (firstWord != sstpPacketTypeData) {
      throw ParseException('not a data packet');
    }
    final sstpLength = r.readUint16();
    if (sstpLength != data.length) {
      throw ParseException('sstp length $sstpLength != actual ${data.length}');
    }
    final hdlc = r.readUint16();
    if (hdlc != pppHdlcHeader) {
      throw ParseException('bad HDLC header 0x${hdlc.toRadixString(16)}');
    }
    final protocol = r.readUint16();
    final code = r.readByte();
    final id = r.readByte();
    final pppLength = r.readUint16();
    // pppLength counts code..end. Body is pppLength - 4.
    final bodyLen = pppLength - 4;
    if (bodyLen < 0) {
      throw ParseException('ppp length $pppLength too small');
    }
    final body = r.readBytes(bodyLen);
    return PppFrameView(protocol, code, id, body);
  }
}

/// Builds an SSTP data packet wrapping a PPP frame whose body is [body]
/// (everything after the 4-byte PPP header).
Uint8List buildPppFrame({
  required int protocol,
  required int code,
  required int id,
  required Uint8List body,
}) {
  final pppLength = 4 + body.length; // code, id, length, body
  final sstpLength = pppHeaderOffset + pppLength;
  final w = ByteWriter();
  w.writeUint16(sstpPacketTypeData);
  w.writeUint16(sstpLength);
  w.writeUint16(pppHdlcHeader);
  w.writeUint16(protocol);
  w.writeByte(code);
  w.writeByte(id);
  w.writeUint16(pppLength);
  w.writeBytes(body);
  return w.toBytes();
}

/// Builds an SSTP *data* packet carrying a raw IP datagram. Unlike control
/// frames, a data frame has no code/id/length header: the IP packet follows the
/// 8-byte prefix (SSTP header + HDLC + protocol) directly.
Uint8List buildIpDataPacket(int protocol, Uint8List ipPacket) {
  final sstpLength = pppHeaderOffset + ipPacket.length;
  final w = ByteWriter();
  w.writeUint16(sstpPacketTypeData);
  w.writeUint16(sstpLength);
  w.writeUint16(pppHdlcHeader);
  w.writeUint16(protocol);
  w.writeBytes(ipPacket);
  return w.toBytes();
}

// ---------------------------------------------------------------------------
// PPP configuration options (LCP + IPCP)
// ---------------------------------------------------------------------------

/// A single PPP option: type(1) length(1) value(length-2).
class PppOption {
  final int type;
  final Uint8List value;

  PppOption(this.type, this.value);

  int get length => 2 + value.length;

  void write(ByteWriter w) {
    w.writeByte(type);
    w.writeByte(length);
    w.writeBytes(value);
  }

  /// Parses one option at the reader's current position.
  static PppOption read(ByteReader r) {
    final type = r.readByte();
    final len = r.readByte();
    if (len < 2) {
      throw ParseException('option length $len < 2');
    }
    final value = r.readBytes(len - 2);
    return PppOption(type, value);
  }

  /// Parses a sequence of options filling [totalLen] bytes.
  static List<PppOption> readAll(ByteReader r, int totalLen) {
    final end = r.offset + totalLen;
    final out = <PppOption>[];
    while (r.offset < end) {
      out.add(PppOption.read(r));
    }
    return out;
  }

  static Uint8List writeAll(List<PppOption> options) {
    final w = ByteWriter();
    for (final o in options) {
      o.write(w);
    }
    return w.toBytes();
  }

  @override
  String toString() => 'opt(type=$type, value=${toHex(value)})';
}

// LCP option types.
const int lcpOptionMru = 1;
const int lcpOptionAuth = 3;
const int chapAlgorithmMschapV2 = 0x81;

// IPCP option types.
const int ipcpOptionIpAddress = 0x03;
const int ipcpOptionPrimaryDns = 0x81;
const int ipcpOptionSecondaryDns = 0x83;

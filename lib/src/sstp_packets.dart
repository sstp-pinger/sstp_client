import 'dart:typed_data';

import 'bytes.dart';

// SSTP header: version(0x10) flags(1) length(2, big-endian, whole packet).
// The reference implementation reads version+flags as a single 16-bit word,
// which yields these two discriminator constants.
const int sstpPacketTypeData = 0x1000;
const int sstpPacketTypeControl = 0x1001;

// Control message types (MS-SSTP 2.2.3).
const int sstpMsgCallConnectRequest = 1;
const int sstpMsgCallConnectAck = 2;
const int sstpMsgCallConnectNak = 3;
const int sstpMsgCallConnected = 4;
const int sstpMsgCallAbort = 5;
const int sstpMsgCallDisconnect = 6;
const int sstpMsgCallDisconnectAck = 7;
const int sstpMsgEchoRequest = 8;
const int sstpMsgEchoResponse = 9;

// Attribute IDs (MS-SSTP 2.2.4).
const int sstpAttrEncapsulatedProtocolId = 1;
const int sstpAttrStatusInfo = 2;
const int sstpAttrCryptoBinding = 3;
const int sstpAttrCryptoBindingReq = 4;

// Cert hash protocol bitmask values.
const int certHashProtocolSha1 = 1;
const int certHashProtocolSha256 = 2;

/// Human-readable name for a control message type (for logging).
String sstpMsgName(int type) {
  switch (type) {
    case sstpMsgCallConnectRequest:
      return 'Call-Connect-Request';
    case sstpMsgCallConnectAck:
      return 'Call-Connect-Ack';
    case sstpMsgCallConnectNak:
      return 'Call-Connect-Nak';
    case sstpMsgCallConnected:
      return 'Call-Connected';
    case sstpMsgCallAbort:
      return 'Call-Abort';
    case sstpMsgCallDisconnect:
      return 'Call-Disconnect';
    case sstpMsgCallDisconnectAck:
      return 'Call-Disconnect-Ack';
    case sstpMsgEchoRequest:
      return 'Echo-Request';
    case sstpMsgEchoResponse:
      return 'Echo-Response';
    default:
      return 'Unknown(0x${type.toRadixString(16)})';
  }
}

/// Base class for parsed SSTP control packets.
///
/// The common 8-byte control header is version+flags(2) length(2)
/// messageType(2) numAttributes(2).
abstract class SstpControlPacket {
  int get messageType;

  /// Serialize the full packet including SSTP + control header.
  Uint8List toBytes();

  /// Writes the 8-byte control header given a known total [length] and
  /// [numAttributes].
  static void writeHeader(
      ByteWriter w, int totalLength, int messageType, int numAttributes) {
    w.writeUint16(sstpPacketTypeControl); // version 0x10 + control flag 0x01
    w.writeUint16(totalLength);
    w.writeUint16(messageType);
    w.writeUint16(numAttributes);
  }

  /// Parses any control packet from a full SSTP frame [data].
  /// Returns a typed instance for the message types this client handles, or a
  /// [SstpGenericControl] for the rest.
  static SstpControlPacket parse(Uint8List data) {
    final r = ByteReader(data);
    final firstWord = r.readUint16();
    if (firstWord != sstpPacketTypeControl) {
      throw ParseException(
          'not a control packet (word=0x${firstWord.toRadixString(16)})');
    }
    final length = r.readUint16();
    if (length != data.length) {
      throw ParseException(
          'control length field $length != actual ${data.length}');
    }
    final messageType = r.readUint16();
    final numAttributes = r.readUint16();

    switch (messageType) {
      case sstpMsgCallConnectAck:
        return SstpCallConnectAck.parseBody(r, numAttributes);
      case sstpMsgCallConnectNak:
        return SstpCallConnectNak.parseBody(r, numAttributes, data);
      case sstpMsgCallDisconnect:
      case sstpMsgCallAbort:
        return SstpGenericControl(messageType, _readStatusInfos(r, numAttributes));
      default:
        return SstpGenericControl(messageType, const []);
    }
  }

  static List<StatusInfo> _readStatusInfos(ByteReader r, int numAttributes) {
    final infos = <StatusInfo>[];
    for (var i = 0; i < numAttributes; i++) {
      // Only StatusInfo is expected in terminate packets; stop on anything else.
      if (r.remaining < 4) break;
      final type = r.peekByte(1);
      if (type == sstpAttrStatusInfo) {
        infos.add(StatusInfo.read(r));
      } else {
        break;
      }
    }
    return infos;
  }
}

/// A control packet the client observes but does not model in detail
/// (echo request/response, disconnect, abort, disconnect-ack).
class SstpGenericControl extends SstpControlPacket {
  @override
  final int messageType;
  final List<StatusInfo> statusInfos;

  SstpGenericControl(this.messageType, this.statusInfos);

  @override
  Uint8List toBytes() {
    final w = ByteWriter();
    SstpControlPacket.writeHeader(w, 8, messageType, 0);
    return w.toBytes();
  }
}

/// SSTP_MSG_CALL_CONNECT_REQUEST with a single Encapsulated-Protocol-ID
/// attribute (protocol = PPP = 1). Fixed 14 bytes.
class SstpCallConnectRequest extends SstpControlPacket {
  @override
  int get messageType => sstpMsgCallConnectRequest;

  static const int protocolPpp = 1;

  @override
  Uint8List toBytes() {
    final w = ByteWriter();
    SstpControlPacket.writeHeader(w, 14, messageType, 1);
    // Encapsulated Protocol ID attribute: reserved(1) id(1) length(2=6) value(2).
    w.writeByte(0);
    w.writeByte(sstpAttrEncapsulatedProtocolId);
    w.writeUint16(6);
    w.writeUint16(protocolPpp);
    return w.toBytes();
  }
}

/// SSTP_MSG_CALL_CONNECT_ACK: carries the Crypto-Binding-Request attribute
/// (hash bitmask + 32-byte server nonce). Fixed 48 bytes.
class SstpCallConnectAck extends SstpControlPacket {
  @override
  int get messageType => sstpMsgCallConnectAck;

  final int hashBitmask;
  final Uint8List nonce; // 32 bytes

  SstpCallConnectAck(this.hashBitmask, this.nonce);

  static SstpCallConnectAck parseBody(ByteReader r, int numAttributes) {
    if (numAttributes != 1) {
      throw ParseException('Call-Connect-Ack numAttributes=$numAttributes');
    }
    // Crypto Binding Request attribute: reserved(1) id(1) length(2)
    // then reserved(3) hashBitmask(1) nonce(32).
    r.skip(1);
    final id = r.readByte();
    if (id != sstpAttrCryptoBindingReq) {
      throw ParseException('expected crypto-binding-req, got id=$id');
    }
    final attrLen = r.readUint16();
    if (attrLen != 40) {
      throw ParseException('crypto-binding-req length=$attrLen (want 40)');
    }
    r.skip(3);
    final bitmask = r.readByte();
    final nonce = r.readBytes(32);
    return SstpCallConnectAck(bitmask, nonce);
  }

  @override
  Uint8List toBytes() {
    final w = ByteWriter();
    SstpControlPacket.writeHeader(w, 48, messageType, 1);
    w.writeByte(0);
    w.writeByte(sstpAttrCryptoBindingReq);
    w.writeUint16(40);
    w.writeZeros(3);
    w.writeByte(hashBitmask);
    w.writeBytes(nonce);
    return w.toBytes();
  }
}

/// SSTP_MSG_CALL_CONNECT_NAK: one or more Status-Info attributes describing why
/// the server refused. Modeled enough to log the failure.
class SstpCallConnectNak extends SstpControlPacket {
  @override
  int get messageType => sstpMsgCallConnectNak;

  final List<StatusInfo> statusInfos;

  SstpCallConnectNak(this.statusInfos);

  static SstpCallConnectNak parseBody(
      ByteReader r, int numAttributes, Uint8List data) {
    final infos = <StatusInfo>[];
    for (var i = 0; i < numAttributes; i++) {
      infos.add(StatusInfo.read(r));
    }
    return SstpCallConnectNak(infos);
  }

  @override
  Uint8List toBytes() {
    throw UnsupportedError('client does not send Call-Connect-Nak');
  }
}

/// SSTP_MSG_CALL_CONNECTED with the Crypto-Binding attribute. Fixed 112 bytes.
///
/// Layout of the binding attribute value: reserved(3) hashProtocol(1)
/// nonce(32) certHash(32) compoundMac(32).
class SstpCallConnected extends SstpControlPacket {
  @override
  int get messageType => sstpMsgCallConnected;

  final int hashProtocol;
  final Uint8List nonce; // 32
  final Uint8List certHash; // 32
  Uint8List compoundMac; // 32, filled in after MAC computation

  SstpCallConnected({
    required this.hashProtocol,
    required this.nonce,
    required this.certHash,
    Uint8List? compoundMac,
  }) : compoundMac = compoundMac ?? Uint8List(32);

  /// Serializes the packet. When [zeroMac] is true the compound MAC field is
  /// written as zeros — this is the exact byte sequence the CMAC is computed
  /// over before the real MAC is inserted.
  Uint8List toBytesRaw({required bool zeroMac}) {
    final w = ByteWriter();
    SstpControlPacket.writeHeader(w, 112, messageType, 1);
    // Crypto Binding attribute: reserved(1) id(1) length(2=104) value(104).
    w.writeByte(0);
    w.writeByte(sstpAttrCryptoBinding);
    w.writeUint16(104);
    w.writeZeros(3);
    w.writeByte(hashProtocol);
    w.writeBytes(nonce);
    w.writeBytes(certHash);
    w.writeBytes(zeroMac ? Uint8List(32) : compoundMac);
    return w.toBytes();
  }

  @override
  Uint8List toBytes() => toBytesRaw(zeroMac: false);
}

/// SSTP Status-Info attribute (MS-SSTP 2.2.7): a per-attribute failure report.
class StatusInfo {
  final int attribId; // the attribute the status refers to
  final int status;
  final Uint8List holder;

  StatusInfo(this.attribId, this.status, this.holder);

  static StatusInfo read(ByteReader r) {
    r.skip(1); // reserved
    final id = r.readByte();
    if (id != sstpAttrStatusInfo) {
      throw ParseException('expected status-info attr, got id=$id');
    }
    final len = r.readUint16();
    // value: reserved(3) attribId(1) status(4) holder(len-12)
    r.skip(3);
    final attribId = r.readByte();
    final status = r.readUint32();
    final holderSize = len - 12;
    final holder = holderSize > 0 ? r.readBytes(holderSize) : Uint8List(0);
    return StatusInfo(attribId, status, holder);
  }

  @override
  String toString() =>
      'StatusInfo(attrib=$attribId, status=$status, holder=${toHex(holder)})';
}

import 'dart:typed_data';

/// A growable, big-endian-by-default byte writer.
///
/// SSTP and PPP are network byte order (big-endian) except for a couple of
/// explicitly little-endian fields (the crypto-binding CMAC length), so the
/// endianness is chosen per call.
class ByteWriter {
  final BytesBuilder _builder = BytesBuilder(copy: false);

  int get length => _builder.length;

  void writeByte(int value) => _builder.addByte(value & 0xff);

  void writeBytes(List<int> value) => _builder.add(value);

  void writeUint16(int value, {Endian endian = Endian.big}) {
    final b = ByteData(2)..setUint16(0, value & 0xffff, endian);
    _builder.add(b.buffer.asUint8List());
  }

  void writeUint32(int value, {Endian endian = Endian.big}) {
    final b = ByteData(4)..setUint32(0, value & 0xffffffff, endian);
    _builder.add(b.buffer.asUint8List());
  }

  /// Writes [count] zero bytes (reserved/padding fields).
  void writeZeros(int count) {
    _builder.add(Uint8List(count));
  }

  Uint8List toBytes() => _builder.toBytes();
}

/// A sequential big-endian byte reader with bounds checking.
///
/// Throws [ParseException] rather than [RangeError] so the framer can turn a
/// short/garbled packet into a diagnosable error instead of a raw crash.
class ByteReader {
  final Uint8List _data;
  final ByteData _view;
  int _offset;

  ByteReader(Uint8List data, [int offset = 0])
      : _data = data,
        _view = ByteData.sublistView(data),
        _offset = offset;

  int get offset => _offset;
  int get remaining => _data.length - _offset;

  void _need(int n) {
    if (_offset + n > _data.length) {
      throw ParseException(
          'need $n bytes at offset $_offset but only $remaining remain');
    }
  }

  int readByte() {
    _need(1);
    return _data[_offset++];
  }

  int readUint16({Endian endian = Endian.big}) {
    _need(2);
    final v = _view.getUint16(_offset, endian);
    _offset += 2;
    return v;
  }

  int readUint32({Endian endian = Endian.big}) {
    _need(4);
    final v = _view.getUint32(_offset, endian);
    _offset += 4;
    return v;
  }

  Uint8List readBytes(int n) {
    _need(n);
    final out = Uint8List.sublistView(_data, _offset, _offset + n);
    _offset += n;
    // Copy so callers can retain it independently of the source buffer.
    return Uint8List.fromList(out);
  }

  /// Advances without reading (skips reserved fields).
  void skip(int n) {
    _need(n);
    _offset += n;
  }

  /// Reads the byte at [ahead] bytes past the current position without
  /// advancing. Used to peek at packet/option type discriminators.
  int peekByte(int ahead) {
    _need(ahead + 1);
    return _data[_offset + ahead];
  }
}

/// Thrown when a byte sequence does not match the expected wire format.
class ParseException implements Exception {
  final String message;
  ParseException(this.message);
  @override
  String toString() => 'ParseException: $message';
}

/// Formats [bytes] as a spaced hex dump for failure logging.
String hexDump(List<int> bytes, {int maxBytes = 512}) {
  final n = bytes.length < maxBytes ? bytes.length : maxBytes;
  final sb = StringBuffer();
  for (var i = 0; i < n; i++) {
    if (i > 0 && i % 16 == 0) sb.write('\n');
    sb.write(bytes[i].toRadixString(16).padLeft(2, '0'));
    sb.write(' ');
  }
  if (bytes.length > maxBytes) {
    sb.write('... (${bytes.length - maxBytes} more bytes)');
  }
  return sb.toString();
}

/// Uppercase hex string with no separators (used for MSCHAPv2 authenticator).
String toHex(List<int> bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

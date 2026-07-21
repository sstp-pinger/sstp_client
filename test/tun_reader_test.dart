@TestOn('linux')
library;

import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:sstp_client/src/libc.dart';
import 'package:sstp_client/src/logging.dart';
import 'package:sstp_client/src/tun_reader.dart';
import 'package:test/test.dart';

Logger silentLog() => Logger(level: LogLevel.error, sink: (_) {});

/// Writes [data] to fd [fd] via libc.write.
void writeFd(Libc libc, int fd, List<int> data) {
  final buf = calloc<Uint8>(data.length);
  buf.asTypedList(data.length).setAll(0, data);
  final n = libc.write(fd, buf.cast<Void>(), data.length);
  calloc.free(buf);
  expect(n, data.length);
}

void main() {
  test('reader isolate forwards packets from a pipe and stops cleanly',
      () async {
    final libc = Libc();
    final fds = calloc<Int32>(2);
    expect(libc.pipe(fds), 0, reason: 'pipe() should succeed');
    final readFd = fds[0];
    final writeFd0 = fds[1];
    calloc.free(fds);

    final received = <Uint8List>[];
    final reader = TunReader(
      fd: readFd,
      bufSize: 2048,
      onPacket: received.add,
      log: silentLog(),
    );
    await reader.start();

    // Feed three "packets" through the pipe.
    writeFd(libc, writeFd0, [0x45, 0x00, 0x01, 0x02]);
    await Future<void>.delayed(const Duration(milliseconds: 300));
    writeFd(libc, writeFd0, List<int>.generate(100, (i) => i & 0xff));
    await Future<void>.delayed(const Duration(milliseconds: 300));
    writeFd(libc, writeFd0, [0xFF]);
    await Future<void>.delayed(const Duration(milliseconds: 300));

    expect(received.length, greaterThanOrEqualTo(3));
    expect(received[0], equals([0x45, 0x00, 0x01, 0x02]));
    expect(received[1].length, 100);
    expect(received[2], equals([0xFF]));

    // Clean stop: should return promptly (well under the poll timeout budget).
    final sw = Stopwatch()..start();
    await reader.stop();
    sw.stop();
    expect(sw.elapsed.inSeconds, lessThan(2));

    // After stop, further writes are not delivered.
    final countAfterStop = received.length;
    writeFd(libc, writeFd0, [0x01, 0x02, 0x03]);
    await Future<void>.delayed(const Duration(milliseconds: 300));
    expect(received.length, countAfterStop);

    libc.close(writeFd0);
    libc.close(readFd);
  });
}

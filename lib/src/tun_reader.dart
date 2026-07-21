import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'libc.dart';
import 'logging.dart';

/// Owns a dedicated isolate that polls a file descriptor and forwards inbound
/// packets to the main isolate. Kept separate so a blocking read never stalls
/// the SSTP event loop.
///
/// Public (within `src/`) so it can be validated against a pipe fd in tests,
/// independent of a real TUN device.
class TunReader {
  final int fd;
  final int bufSize;
  final void Function(Uint8List) onPacket;
  final Logger log;

  Isolate? _iso;
  ReceivePort? _rp;
  SendPort? _control;
  Completer<void>? _stopped;

  TunReader({
    required this.fd,
    required this.bufSize,
    required this.onPacket,
    required this.log,
  });

  Future<void> start() async {
    _rp = ReceivePort();
    final ready = Completer<void>();
    _rp!.listen((msg) {
      if (msg is SendPort) {
        _control = msg;
        if (!ready.isCompleted) ready.complete();
      } else if (msg is Uint8List) {
        onPacket(msg);
      } else if (msg == 'stopped') {
        _stopped?.complete();
      }
    });
    _iso = await Isolate.spawn(
      _tunReaderEntry,
      _ReaderArgs(_rp!.sendPort, fd, bufSize),
    );
    await ready.future.timeout(const Duration(seconds: 3),
        onTimeout: () => throw StateError('reader isolate did not start'));
  }

  /// Signals the reader to stop, waits for it to free native buffers and exit,
  /// then kills the isolate. Safe to call once.
  Future<void> stop() async {
    _stopped = Completer<void>();
    _control?.send('stop');
    if (_control != null) {
      await _stopped!.future
          .timeout(const Duration(seconds: 2), onTimeout: () {});
    }
    _rp?.close();
    _iso?.kill(priority: Isolate.immediate);
    _iso = null;
  }
}

class _ReaderArgs {
  final SendPort toMain;
  final int fd;
  final int bufSize;
  _ReaderArgs(this.toMain, this.fd, this.bufSize);
}

/// Reader isolate entrypoint. Polls the fd with a short timeout so it can react
/// to a 'stop' control message between iterations, freeing native buffers on
/// exit.
Future<void> _tunReaderEntry(_ReaderArgs args) async {
  final libc = Libc();
  final control = ReceivePort();
  args.toMain.send(control.sendPort);

  var stop = false;
  control.listen((msg) {
    if (msg == 'stop') stop = true;
  });

  final buf = calloc<Uint8>(args.bufSize);
  // struct pollfd { int fd; short events; short revents; } = 8 bytes.
  final pollfd = calloc<Uint8>(8);
  final pollView = pollfd.asTypedList(8);
  pollfd.cast<Int32>().value = args.fd; // fd @0
  pollView[4] = pollin & 0xff; // events @4 (short, little-endian)
  pollView[5] = (pollin >> 8) & 0xff;

  try {
    while (!stop) {
      pollView[6] = 0; // clear revents @6
      pollView[7] = 0;
      final n = libc.poll(pollfd.cast<Void>(), 1, 200);
      if (n > 0) {
        final revents = pollView[6] | (pollView[7] << 8);
        if (revents & pollin != 0) {
          final len = libc.read(args.fd, buf.cast<Void>(), args.bufSize);
          if (len > 0) {
            args.toMain.send(Uint8List.fromList(buf.asTypedList(len)));
          } else if (len == 0) {
            // EOF (e.g. pipe write end closed): stop cleanly.
            break;
          }
        }
      }
      // Yield so queued control messages ('stop') are processed.
      await Future<void>.delayed(Duration.zero);
    }
  } finally {
    calloc.free(buf);
    calloc.free(pollfd);
    args.toMain.send('stopped');
    control.close();
  }
}

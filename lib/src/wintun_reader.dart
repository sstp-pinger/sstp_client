import 'dart:async';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'logging.dart';
import 'wintun.dart';

/// Owns a dedicated isolate that waits on Wintun's read event and forwards
/// inbound packets (packets the OS stack is sending outbound) to the main
/// isolate. Kept separate so the blocking `WaitForMultipleObjects` never stalls
/// the SSTP event loop.
///
/// This is the Windows analog of `TunReader`: same "blocking read lives in its
/// own isolate" shape, but event-driven (the read-wait event + a stop event)
/// rather than a `poll()` timeout tick.
class WintunReader {
  /// Process-global handles, passed as integer addresses so the isolate can
  /// reconstruct them: the Wintun session, its read-wait event, and a
  /// manual-reset stop event the owner signals to unblock the wait.
  final int sessionAddr;
  final int readEventAddr;
  final int stopEventAddr;
  final int mtu;
  final void Function(Uint8List) onPacket;
  final Logger log;
  final String dllPath;

  Isolate? _iso;
  ReceivePort? _rp;
  Completer<void>? _stopped;

  WintunReader({
    required this.sessionAddr,
    required this.readEventAddr,
    required this.stopEventAddr,
    required this.mtu,
    required this.onPacket,
    required this.log,
    this.dllPath = 'wintun.dll',
  });

  Future<void> start() async {
    _rp = ReceivePort();
    final ready = Completer<void>();
    _rp!.listen((msg) {
      if (msg == 'ready') {
        if (!ready.isCompleted) ready.complete();
      } else if (msg is Uint8List) {
        onPacket(msg);
      } else if (msg == 'stopped') {
        _stopped?.complete();
      }
    });
    _iso = await Isolate.spawn(
      _wintunReaderEntry,
      _ReaderArgs(
        _rp!.sendPort,
        sessionAddr,
        readEventAddr,
        stopEventAddr,
        dllPath,
      ),
    );
    await ready.future.timeout(const Duration(seconds: 3),
        onTimeout: () => throw StateError('wintun reader isolate did not start'));
  }

  /// Signals the stop event, waits for the isolate to exit its wait loop, then
  /// kills it. The caller is responsible for `WintunEndSession` afterwards
  /// (which is what makes the read event stop firing). Safe to call once.
  Future<void> stop() async {
    _stopped = Completer<void>();
    // Signal the stop event so WaitForMultipleObjects returns immediately.
    final wintun = Wintun(dllPath: dllPath);
    wintun.setEvent(Pointer<Void>.fromAddress(stopEventAddr));
    await _stopped!.future
        .timeout(const Duration(seconds: 2), onTimeout: () {});
    _rp?.close();
    _iso?.kill(priority: Isolate.immediate);
    _iso = null;
  }
}

class _ReaderArgs {
  final SendPort toMain;
  final int sessionAddr;
  final int readEventAddr;
  final int stopEventAddr;
  final String dllPath;
  _ReaderArgs(this.toMain, this.sessionAddr, this.readEventAddr,
      this.stopEventAddr, this.dllPath);
}

/// Reader isolate entrypoint. Waits on [readEvent, stopEvent]; when the read
/// event fires, drains every queued packet until `ERROR_NO_MORE_ITEMS`, copying
/// each into a [Uint8List] for the main isolate; when the stop event fires,
/// exits cleanly.
void _wintunReaderEntry(_ReaderArgs args) {
  final wintun = Wintun(dllPath: args.dllPath);
  final session = Pointer<Void>.fromAddress(args.sessionAddr);

  // HANDLE array for WaitForMultipleObjects: [0]=read, [1]=stop.
  final handles = calloc<Pointer<Void>>(2);
  handles[0] = Pointer<Void>.fromAddress(args.readEventAddr);
  handles[1] = Pointer<Void>.fromAddress(args.stopEventAddr);
  final sizePtr = calloc<Uint32>();

  args.toMain.send('ready');

  try {
    var running = true;
    while (running) {
      final w = wintun.waitForMultipleObjects(2, handles, 0, infinite);
      if (w == waitObject0 + 1 || w == waitFailed) {
        break; // stop event, or the wait failed (e.g. session ended)
      }
      // Read event (or a spurious wake): drain the ring.
      while (true) {
        final pkt = wintun.receivePacket(session, sizePtr);
        if (pkt == nullptr) {
          // Empty ring is the normal exit; anything else ends the loop too.
          break;
        }
        final size = sizePtr.value;
        args.toMain.send(Uint8List.fromList(pkt.asTypedList(size)));
        wintun.releaseReceivePacket(session, pkt);
      }
    }
  } finally {
    calloc.free(handles);
    calloc.free(sizePtr);
    args.toMain.send('stopped');
  }
}

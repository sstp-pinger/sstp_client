import 'dart:ffi';

import 'package:ffi/ffi.dart';

/// Thin binding to the handful of Wintun (wintun.dll) and kernel32 entry points
/// the Windows TUN backend needs.
///
/// Wintun is WireGuard's userspace TUN driver for Windows. Unlike Linux's
/// `/dev/net/tun`, there is no file descriptor: an adapter is created through
/// the DLL, and packets move over a ring-buffer "session" whose readable side is
/// signalled by a Win32 event (so we can wait on it instead of busy-polling).
///
/// Constructed per-isolate (native handles/library handles are not shared across
/// isolates, though the adapter/session *object* handles are process-global and
/// may be passed between isolates as integer addresses).
///
/// Kept in `src/` so the surrounding logic (e.g. route parsing) can be tested
/// without a real adapter, which requires Administrator on Windows.
class Wintun {
  final DynamicLibrary _lib;
  final DynamicLibrary _k32;

  // -- Wintun adapter/session lifecycle --
  late final Pointer<Void> Function(
      Pointer<Utf16>, Pointer<Utf16>, Pointer<Void>) createAdapter;
  late final void Function(Pointer<Void>) closeAdapter;
  late final Pointer<Void> Function(Pointer<Void>, int) startSession;
  late final void Function(Pointer<Void>) endSession;
  late final Pointer<Void> Function(Pointer<Void>) getReadWaitEvent;

  // -- Wintun data path --
  late final Pointer<Uint8> Function(Pointer<Void>, Pointer<Uint32>)
      receivePacket;
  late final void Function(Pointer<Void>, Pointer<Uint8>) releaseReceivePacket;
  late final Pointer<Uint8> Function(Pointer<Void>, int) allocateSendPacket;
  late final void Function(Pointer<Void>, Pointer<Uint8>) sendPacket;

  // -- kernel32 (event + error handling) --
  late final Pointer<Void> Function(Pointer<Void>, int, int, Pointer<Utf16>)
      createEvent;
  late final int Function(Pointer<Void>) setEvent;
  late final int Function(Pointer<Void>) closeHandle;
  late final int Function(int, Pointer<Pointer<Void>>, int, int)
      waitForMultipleObjects;
  late final int Function() getLastError;

  Wintun({String dllPath = 'wintun.dll'})
      : _lib = DynamicLibrary.open(dllPath),
        _k32 = DynamicLibrary.open('kernel32.dll') {
    createAdapter = _lib.lookupFunction<
        Pointer<Void> Function(Pointer<Utf16>, Pointer<Utf16>, Pointer<Void>),
        Pointer<Void> Function(Pointer<Utf16>, Pointer<Utf16>,
            Pointer<Void>)>('WintunCreateAdapter');
    closeAdapter = _lib.lookupFunction<Void Function(Pointer<Void>),
        void Function(Pointer<Void>)>('WintunCloseAdapter');
    startSession = _lib.lookupFunction<
        Pointer<Void> Function(Pointer<Void>, Uint32),
        Pointer<Void> Function(Pointer<Void>, int)>('WintunStartSession');
    endSession = _lib.lookupFunction<Void Function(Pointer<Void>),
        void Function(Pointer<Void>)>('WintunEndSession');
    getReadWaitEvent = _lib.lookupFunction<
        Pointer<Void> Function(Pointer<Void>),
        Pointer<Void> Function(Pointer<Void>)>('WintunGetReadWaitEvent');

    receivePacket = _lib.lookupFunction<
        Pointer<Uint8> Function(Pointer<Void>, Pointer<Uint32>),
        Pointer<Uint8> Function(
            Pointer<Void>, Pointer<Uint32>)>('WintunReceivePacket');
    releaseReceivePacket = _lib.lookupFunction<
        Void Function(Pointer<Void>, Pointer<Uint8>),
        void Function(
            Pointer<Void>, Pointer<Uint8>)>('WintunReleaseReceivePacket');
    allocateSendPacket = _lib.lookupFunction<
        Pointer<Uint8> Function(Pointer<Void>, Uint32),
        Pointer<Uint8> Function(
            Pointer<Void>, int)>('WintunAllocateSendPacket');
    sendPacket = _lib.lookupFunction<
        Void Function(Pointer<Void>, Pointer<Uint8>),
        void Function(Pointer<Void>, Pointer<Uint8>)>('WintunSendPacket');

    createEvent = _k32.lookupFunction<
        Pointer<Void> Function(Pointer<Void>, Int32, Int32, Pointer<Utf16>),
        Pointer<Void> Function(
            Pointer<Void>, int, int, Pointer<Utf16>)>('CreateEventW');
    setEvent = _k32.lookupFunction<Int32 Function(Pointer<Void>),
        int Function(Pointer<Void>)>('SetEvent');
    closeHandle = _k32.lookupFunction<Int32 Function(Pointer<Void>),
        int Function(Pointer<Void>)>('CloseHandle');
    waitForMultipleObjects = _k32.lookupFunction<
        Uint32 Function(Uint32, Pointer<Pointer<Void>>, Int32, Uint32),
        int Function(int, Pointer<Pointer<Void>>, int,
            int)>('WaitForMultipleObjects');
    getLastError = _k32.lookupFunction<Uint32 Function(), int Function()>(
        'GetLastError');
  }

  /// Creates a manual-reset event, initially non-signalled. Used as the stop
  /// signal for the reader isolate's [waitForMultipleObjects].
  Pointer<Void> createStopEvent() =>
      createEvent(nullptr, 1, 0, nullptr); // bManualReset=TRUE, initial=FALSE
}

// Wintun ring capacity (bytes, power of two in [128KiB, 64MiB]). 4 MiB is
// WireGuard's own default and comfortably absorbs bursts.
const int wintunRingCapacity = 0x400000;

// Win32 constants.
const int errorAccessDenied = 5; // ERROR_ACCESS_DENIED
const int errorNoMoreItems = 259; // ERROR_NO_MORE_ITEMS (ring drained)
const int infinite = 0xFFFFFFFF; // INFINITE
const int waitObject0 = 0; // WAIT_OBJECT_0
const int waitFailed = 0xFFFFFFFF; // WAIT_FAILED

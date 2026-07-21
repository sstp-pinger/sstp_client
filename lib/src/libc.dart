import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';

/// Thin binding to the handful of libc syscalls the Linux TUN and macOS utun
/// backends need.
///
/// Constructed per-isolate (native library handles are not shared across
/// isolates). Kept in `src/` so tests can exercise the reader isolate against a
/// pipe without needing a real TUN device (which requires root).
class Libc {
  final DynamicLibrary _lib;

  late final int Function(Pointer<Utf8>, int) open;
  late final int Function(int, int, Pointer<Void>) ioctl;
  late final int Function(int, Pointer<Void>, int) read;
  late final int Function(int, Pointer<Void>, int) write;
  late final int Function(int) close;
  late final int Function(Pointer<Void>, int, int) poll;
  late final int Function(Pointer<Int32>) pipe;

  // Used by the macOS utun backend (present on Linux too, harmless to bind).
  late final int Function(int, int, int) socket;
  late final int Function(int, Pointer<Void>, int) connect;
  late final int Function(int, int, int, Pointer<Void>, Pointer<Uint32>)
      getsockopt;

  late final Pointer<Int32> Function() _errnoLocation;

  Libc()
      : _lib = DynamicLibrary.open(
            Platform.isMacOS ? 'libSystem.dylib' : 'libc.so.6') {
    open = _lib.lookupFunction<Int32 Function(Pointer<Utf8>, Int32),
        int Function(Pointer<Utf8>, int)>('open');

    // ioctl is variadic: `int ioctl(int, unsigned long, ...)`. The third
    // argument MUST be declared with VarArgs, not as a fixed parameter.
    // On x86-64 both conventions pass it in the same register, so a fixed
    // declaration happens to work on Linux — but on arm64 (Apple Silicon)
    // variadic arguments are passed on the stack, so the kernel would read a
    // garbage pointer. That surfaced as ioctl(CTLIOCGINFO) failing with ENOENT.
    ioctl = _lib.lookupFunction<
        Int32 Function(Int32, UnsignedLong, VarArgs<(Pointer<Void>,)>),
        int Function(int, int, Pointer<Void>)>('ioctl');
    read = _lib.lookupFunction<IntPtr Function(Int32, Pointer<Void>, IntPtr),
        int Function(int, Pointer<Void>, int)>('read');
    write = _lib.lookupFunction<IntPtr Function(Int32, Pointer<Void>, IntPtr),
        int Function(int, Pointer<Void>, int)>('write');
    close = _lib.lookupFunction<Int32 Function(Int32), int Function(int)>(
        'close');
    poll = _lib.lookupFunction<Int32 Function(Pointer<Void>, Uint64, Int32),
        int Function(Pointer<Void>, int, int)>('poll');
    pipe = _lib.lookupFunction<Int32 Function(Pointer<Int32>),
        int Function(Pointer<Int32>)>('pipe');

    socket = _lib.lookupFunction<Int32 Function(Int32, Int32, Int32),
        int Function(int, int, int)>('socket');
    connect = _lib.lookupFunction<Int32 Function(Int32, Pointer<Void>, Uint32),
        int Function(int, Pointer<Void>, int)>('connect');
    getsockopt = _lib.lookupFunction<
        Int32 Function(Int32, Int32, Int32, Pointer<Void>, Pointer<Uint32>),
        int Function(int, int, int, Pointer<Void>,
            Pointer<Uint32>)>('getsockopt');

    // glibc exposes errno via __errno_location(); Darwin uses __error().
    _errnoLocation = _lib.lookupFunction<Pointer<Int32> Function(),
        Pointer<Int32> Function()>(
        Platform.isMacOS ? '__error' : '__errno_location');
  }

  int get errno => _errnoLocation().value;
}

// Syscall constants used across the TUN backends.
const int oRdwr = 0x2; // O_RDWR
const int pollin = 0x001; // POLLIN (same on Linux and Darwin)
const int eperm = 1; // EPERM

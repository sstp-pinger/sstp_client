import 'dart:async';
import 'dart:ffi';
import 'dart:io';

import 'libc.dart';
import 'logging.dart';
import 'wintun.dart';

/// One command that reverts a change a backend made (a route, an address, a DNS
/// setting).
class TeardownCommand {
  final String exe;
  final List<String> args;
  final String label;
  const TeardownCommand(this.exe, this.args, this.label);
}

/// Everything still needed to take a tunnel down, as plain data.
///
/// A backend normally undoes its own changes in `close()`. But the backend
/// lives in a connection isolate, and an isolate that gets killed never runs
/// `close()`: the device stays up with the full-tunnel routes pointing into
/// it, and every connection on the machine goes into a tunnel nobody is
/// serving. So a backend publishes this plan after every change, and whoever
/// killed the isolate passes the last one to [runTeardownPlan].
///
/// Native handles are process-wide, so they are valid in any isolate. A
/// backend drops a handle from the plan in the same synchronous step that
/// frees it, so a killed isolate never leaves a plan naming a freed handle.
class TeardownPlan {
  /// In the order the changes were made; run in reverse.
  final List<TeardownCommand> commands;

  /// Linux: the tun fd. Closing it removes the interface.
  final int? tunFd;

  /// Windows: Wintun handle addresses, 0 when not held.
  final int wintunAdapter;
  final int wintunSession;
  final int wintunStopEvent;
  final String? wintunDll;

  const TeardownPlan({
    this.commands = const [],
    this.tunFd,
    this.wintunAdapter = 0,
    this.wintunSession = 0,
    this.wintunStopEvent = 0,
    this.wintunDll,
  });

  bool get isEmpty =>
      commands.isEmpty &&
      tunFd == null &&
      wintunAdapter == 0 &&
      wintunSession == 0 &&
      wintunStopEvent == 0;
}

/// Takes down what [plan] describes, from an isolate other than the one that
/// built the tunnel. Call it only once that isolate has exited. Every step is
/// best-effort: one failure must not leave the rest in place.
Future<void> runTeardownPlan(TeardownPlan plan, Logger log) async {
  if (plan.isEmpty) return;
  log.info('TUN', 'cleaning up after a stopped connection');

  Wintun? wintun;
  if (plan.wintunSession != 0 || plan.wintunAdapter != 0 ||
      plan.wintunStopEvent != 0) {
    try {
      wintun = Wintun(dllPath: plan.wintunDll ?? 'wintun.dll');
    } catch (e) {
      log.warn('TUN', 'could not load wintun for cleanup: $e');
    }
  }

  if (wintun != null && plan.wintunStopEvent != 0) {
    // Releases the reader isolate's wait, so it is not inside the session
    // when the session ends.
    wintun.setEvent(Pointer<Void>.fromAddress(plan.wintunStopEvent));
    await Future<void>.delayed(const Duration(milliseconds: 300));
  }
  if (wintun != null && plan.wintunSession != 0) {
    wintun.endSession(Pointer<Void>.fromAddress(plan.wintunSession));
  }

  for (final c in plan.commands.reversed) {
    try {
      final r = await Process.run(c.exe, c.args)
          .timeout(const Duration(seconds: 15));
      log.debug('TUN', r.exitCode == 0
          ? 'reverted: ${c.label}'
          : 'undo "${c.label}" exited ${r.exitCode}');
    } catch (e) {
      log.debug('TUN', 'undo "${c.label}" failed: $e');
    }
  }

  if (wintun != null && plan.wintunAdapter != 0) {
    // Removes the adapter, and with it every route still bound to it.
    wintun.closeAdapter(Pointer<Void>.fromAddress(plan.wintunAdapter));
  }
  if (wintun != null && plan.wintunStopEvent != 0) {
    wintun.closeHandle(Pointer<Void>.fromAddress(plan.wintunStopEvent));
  }
  if (plan.tunFd != null) {
    Libc().close(plan.tunFd!); // removes the interface
  }
  log.info('TUN', 'cleanup complete');
}

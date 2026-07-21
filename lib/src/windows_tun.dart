import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'logging.dart';
import 'tunnel_backend.dart';
import 'wintun.dart';
import 'wintun_reader.dart';

/// Windows TUN backend: creates a Wintun adapter, moves raw IP packets over a
/// Wintun session (inbound via a dedicated reader isolate, outbound via
/// `WintunAllocateSendPacket`/`WintunSendPacket`), and configures the adapter's
/// address, MTU, and routing with `netsh`/`route`.
///
/// The mirror of [LinuxTunBackend]: same interface, same LIFO-undo teardown, but
/// Wintun in place of `/dev/net/tun` and `netsh`/`route` in place of `ip`.
///
/// `wintun.dll` (from wintun.net, the official signed build matching the host
/// architecture) must be resolvable — next to the executable is simplest.
/// Creating an adapter and changing routes requires an elevated
/// (Administrator) process.
class WindowsTunBackend implements TunnelBackend {
  final Logger log;
  final String dllPath;

  Wintun? _wintun;
  Pointer<Void> _adapter = nullptr;
  Pointer<Void> _session = nullptr;
  Pointer<Void> _stopEvent = nullptr;
  String _ifName = 'tun0';

  // Reverse operations to undo on close(), applied in LIFO order.
  final List<_Undo> _undo = [];

  /// Comment stamped on our NRPT rule so teardown can find and remove exactly
  /// the rule we added, without disturbing any the user set themselves.
  static const String _nrptTag = 'sstp-shield-tun';

  final _inbound = StreamController<Uint8List>.broadcast();
  WintunReader? _reader;

  bool _closed = false;

  WindowsTunBackend({required this.log, this.dllPath = 'wintun.dll'});

  @override
  String get interfaceName => _ifName;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Future<void> open(TunnelConfig config) async {
    _ifName = config.interfaceName;
    _createAdapter(_ifName);
    log.info('TUN', 'created Wintun adapter "$_ifName"');

    // Start the session and reader before routing so no inbound packet is lost.
    final wintun = _wintun!;
    _session = wintun.startSession(_adapter, wintunRingCapacity);
    if (_session == nullptr) {
      final e = wintun.getLastError();
      throw TunnelException('WintunStartSession failed (error=$e)');
    }
    final readEvent = wintun.getReadWaitEvent(_session);
    _stopEvent = wintun.createStopEvent();

    _reader = WintunReader(
      sessionAddr: _session.address,
      readEventAddr: readEvent.address,
      stopEventAddr: _stopEvent.address,
      mtu: config.mtu,
      onPacket: _inbound.add,
      log: log,
      dllPath: dllPath,
    );
    await _reader!.start();

    try {
      await _configureInterface(config);
      await _installRouting(config);
    } catch (_) {
      await close();
      rethrow;
    }
    log.info('TUN',
        'adapter up and routing installed (${config.routeMode.name}-tunnel)');
  }

  void _createAdapter(String name) {
    try {
      _wintun = Wintun(dllPath: dllPath);
    } catch (e) {
      throw TunnelException(
          'could not load $dllPath: $e. Place the official signed wintun.dll '
          '(matching this build\'s architecture) next to the executable.');
    }
    final wintun = _wintun!;
    final namePtr = name.toNativeUtf16();
    final typePtr = 'SSTP'.toNativeUtf16();
    try {
      _adapter = wintun.createAdapter(namePtr, typePtr, nullptr);
      if (_adapter == nullptr) {
        final e = wintun.getLastError();
        if (e == errorAccessDenied) {
          throw TunnelPermissionException(
              'WintunCreateAdapter denied (ERROR_ACCESS_DENIED): creating a '
              'tunnel adapter needs Administrator. Re-run from an elevated '
              'prompt.');
        }
        throw TunnelException('WintunCreateAdapter failed (error=$e)');
      }
    } finally {
      malloc.free(namePtr);
      malloc.free(typePtr);
    }
  }

  Future<void> _configureInterface(TunnelConfig config) async {
    // Disable Duplicate Address Detection *before* assigning the address.
    // Otherwise the address sits in the "Tentative" state for several seconds
    // and cannot be used as a source address — traffic fails until DAD ends.
    // A point-to-point tunnel address is server-assigned, so DAD is pointless.
    await _run(
      'netsh',
      ['interface', 'ipv4', 'set', 'interface', _ifName, 'dadtransmits=0',
        'store=active'],
      label: 'disable DAD',
    );

    // /32 host address; the routes below send traffic on-link via the adapter.
    await _run(
      'netsh',
      ['interface', 'ipv4', 'set', 'address', 'name=$_ifName', 'static',
        config.assignedIp, '255.255.255.255'],
      undo: _Cmd('netsh', ['interface', 'ipv4', 'delete', 'address',
        'name=$_ifName', 'address=${config.assignedIp}']),
      label: 'assign ${config.assignedIp}',
    );
    await _run(
      'netsh',
      ['interface', 'ipv4', 'set', 'subinterface', _ifName,
        'mtu=${config.mtu}', 'store=active'],
      label: 'set mtu ${config.mtu}', // adapter is removed on close; no undo
    );
  }

  Future<void> _installRouting(TunnelConfig config) async {
    final serverIp = config.serverAddress.address;

    if (config.routeMode == RouteMode.full) {
      // Pin the server to the physical path so the SSTP transport survives the
      // default-route override.
      final def = await _defaultRoute();
      if (def == null) {
        throw TunnelException(
            'no existing default route found; cannot pin server route');
      }
      log.debug('TUN', 'original default: via ${def.gateway}');
      await _run(
        'route',
        ['add', serverIp, 'mask', '255.255.255.255', def.gateway, 'metric', '1'],
        undo: _Cmd('route', ['delete', serverIp]),
        label: 'pin server $serverIp via ${def.gateway}',
      );
      // Override the default with two /1 on-link routes via the tunnel (this
      // never touches the real 0.0.0.0/0, so revert is just removing these).
      await _addTunnelRoute('0.0.0.0/1', 'default half 0.0.0.0/1 via tunnel');
      await _addTunnelRoute('128.0.0.0/1', 'default half 128.0.0.0/1 via tunnel');
      // Route DNS through the tunnel too. Otherwise the OS resolver keeps
      // querying the physical adapter's (ISP) DNS even though data now flows
      // through the tunnel — so on a network that poisons or blocks lookups for
      // certain hosts, name resolution fails even though the tunnel itself works.
      await _applyDns(config);
    } else {
      if (config.splitCidrs.isEmpty) {
        log.warn('TUN',
            'split-tunnel requested with no --route CIDRs; no traffic will use the tunnel');
      }
      for (final cidr in config.splitCidrs) {
        await _addTunnelRoute(cidr, 'split route $cidr via tunnel');
      }
    }
  }

  /// Forces name resolution through a DNS server reachable over the tunnel,
  /// bypassing the physical adapter's (ISP) resolver. Best-effort: a DNS-setup
  /// hiccup logs a warning but never tears down an otherwise-working tunnel.
  ///
  /// Two layers: (1) give the tunnel adapter a DNS server, and (2) add a
  /// Name Resolution Policy Table catch-all rule so *every* query is directed at
  /// that resolver and none can leak to — and be poisoned by — the ISP's DNS.
  Future<void> _applyDns(TunnelConfig config) async {
    // Prefer the IPCP-assigned DNS (reachable through the tunnel); fall back to
    // a public resolver, which the /1 routes above also send over the tunnel.
    final dns = (config.dns != null && config.dns!.isNotEmpty)
        ? config.dns!
        : '1.1.1.1';

    // 1) Adapter DNS. The adapter is removed on close, so no undo is needed.
    final setDns = await Process.run('netsh', [
      'interface', 'ipv4', 'set', 'dnsservers',
      'name=$_ifName', 'static', dns, 'primary', 'validate=no',
    ]);
    if (setDns.exitCode != 0) {
      log.warn('TUN', 'could not set adapter DNS: ${_msg(setDns).trim()}');
    } else {
      log.debug('TUN', 'adapter DNS => $dns');
    }

    // 2) NRPT catch-all so no lookup leaks to the physical resolver.
    final add = await Process.run('powershell', [
      '-NoProfile', '-NonInteractive', '-Command',
      "Add-DnsClientNrptRule -Namespace '.' -NameServers '$dns' "
          "-Comment '$_nrptTag'",
    ]);
    if (add.exitCode != 0) {
      log.warn('TUN', 'could not add NRPT rule: ${_msg(add).trim()}');
      return;
    }
    log.debug('TUN', 'NRPT catch-all => $dns');
    _undo.add(_Undo('powershell', [
      '-NoProfile', '-NonInteractive', '-Command',
      "Get-DnsClientNrptRule | Where-Object { \$_.Comment -eq '$_nrptTag' } | "
          "Remove-DnsClientNrptRule -Force",
    ], 'remove NRPT rule'));
  }

  /// Adds an on-link route through the tunnel adapter (no nexthop => on-link,
  /// correct for a point-to-point tunnel).
  Future<void> _addTunnelRoute(String prefix, String label) async {
    await _run(
      'netsh',
      ['interface', 'ipv4', 'add', 'route', 'prefix=$prefix',
        'interface=$_ifName', 'store=active'],
      undo: _Cmd('netsh', ['interface', 'ipv4', 'delete', 'route',
        'prefix=$prefix', 'interface=$_ifName']),
      label: label,
    );
  }

  @override
  Future<void> writePacket(Uint8List packet) async {
    final wintun = _wintun;
    if (wintun == null || _session == nullptr) return;
    final n = packet.length;
    final buf = wintun.allocateSendPacket(_session, n);
    if (buf == nullptr) {
      // Ring full (ERROR_BUFFER_OVERFLOW) — drop, like a congested NIC would.
      log.trace('TUN', 'send ring full; dropped $n-byte packet');
      return;
    }
    buf.asTypedList(n).setAll(0, packet);
    wintun.sendPacket(_session, buf);
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    log.info('TUN', 'tearing down $_ifName');

    // Stop the reader (signals the stop event), then end the session so the
    // read event stops firing.
    await _reader?.stop();
    final wintun = _wintun;
    if (wintun != null && _session != nullptr) {
      wintun.endSession(_session);
      _session = nullptr;
    }

    // Revert routing/address changes in reverse order; tolerate failures.
    for (final u in _undo.reversed) {
      final r = await Process.run(u.exe, u.args);
      if (r.exitCode != 0) {
        log.debug('TUN',
            'undo "${u.label}" exited ${r.exitCode}: ${_msg(r).trim()}');
      } else {
        log.debug('TUN', 'reverted: ${u.label}');
      }
    }
    _undo.clear();

    // Removing the adapter drops any remaining routes/addresses bound to it.
    if (wintun != null && _adapter != nullptr) {
      wintun.closeAdapter(_adapter);
      _adapter = nullptr;
    }
    if (wintun != null && _stopEvent != nullptr) {
      wintun.closeHandle(_stopEvent);
      _stopEvent = nullptr;
    }
    if (!_inbound.isClosed) await _inbound.close();
    log.info('TUN', 'teardown complete');
  }

  // -- helpers -------------------------------------------------------------

  Future<void> _run(String exe, List<String> args,
      {_Cmd? undo, required String label}) async {
    log.debug('TUN', '$exe ${args.join(' ')}');
    final r = await Process.run(exe, args);
    if (r.exitCode != 0) {
      final err = _msg(r).trim();
      if (_looksLikeElevation(err)) {
        throw TunnelPermissionException(
            '$exe ${args.join(' ')} denied: needs Administrator. $err');
      }
      throw TunnelException('$exe ${args.join(' ')} failed: $err');
    }
    if (undo != null) _undo.add(_Undo(undo.exe, undo.args, label));
  }

  Future<WindowsDefaultRoute?> _defaultRoute() async {
    final r = await Process.run('route', ['print', '-4']);
    if (r.exitCode != 0) return null;
    return parseWindowsDefaultRoute(r.stdout as String);
  }

  bool _looksLikeElevation(String s) {
    final l = s.toLowerCase();
    return l.contains('elevation') ||
        l.contains('requested operation requires') ||
        l.contains('access is denied') ||
        l.contains('administrator');
  }

  /// `route`/`netsh` write diagnostics to stdout on Windows; fall back to stderr.
  String _msg(ProcessResult r) {
    final out = (r.stdout as String).trim();
    return out.isNotEmpty ? out : (r.stderr as String);
  }
}

final _ipv4 = RegExp(r'^\d{1,3}(\.\d{1,3}){3}$');

/// Parses the IPv4 default route out of `route print -4` output. The
/// language-independent anchor is the `0.0.0.0  0.0.0.0` (destination + netmask)
/// row in the "Active Routes" table:
///
///     Network Destination  Netmask      Gateway        Interface     Metric
///             0.0.0.0      0.0.0.0   192.168.1.1    192.168.1.42         25
///
/// Only rows whose *gateway and interface* columns are both dotted quads are
/// accepted. That is what distinguishes an Active Routes row from the
/// "Persistent Routes" table further down, whose rows carry a metric
/// (e.g. `Default`) in the 4th column instead of an interface address — a
/// persistent default with a stale gateway would otherwise be picked up here.
/// Checking the column shape rather than the section header keeps this working
/// on non-English Windows.
///
/// Returns null if no default route is present.
WindowsDefaultRoute? parseWindowsDefaultRoute(String routePrintOutput) {
  for (final raw in routePrintOutput.split('\n')) {
    final tokens = raw.trim().split(RegExp(r'\s+'));
    if (tokens.length >= 4 &&
        tokens[0] == '0.0.0.0' &&
        tokens[1] == '0.0.0.0' &&
        _ipv4.hasMatch(tokens[2]) && // gateway (excludes "On-link")
        _ipv4.hasMatch(tokens[3])) {
      // interface address (excludes Persistent rows)
      return WindowsDefaultRoute(tokens[2], tokens[3]);
    }
  }
  return null;
}

class _Undo {
  final String exe;
  final List<String> args;
  final String label;
  _Undo(this.exe, this.args, this.label);
}

class _Cmd {
  final String exe;
  final List<String> args;
  _Cmd(this.exe, this.args);
}

class WindowsDefaultRoute {
  final String gateway;

  /// The interface's own address as reported by `route print` (the 4th column);
  /// kept for diagnostics.
  final String ifaceAddress;
  WindowsDefaultRoute(this.gateway, this.ifaceAddress);
}

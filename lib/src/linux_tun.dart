import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'libc.dart';
import 'linux_dns.dart';
import 'linux_routes.dart';
import 'logging.dart';
import 'teardown_plan.dart';
import 'tun_reader.dart';
import 'tunnel_backend.dart';

// Constants confirmed against this system's headers (see if_tun.h / net/if.h):
//   sizeof(struct ifreq) = 40, ifr_name @0 (16B), ifr_flags @16 (short)
//   TUNSETIFF = 0x400454CA, IFF_TUN|IFF_NO_PI = 0x1001
const int _ifnamsiz = 16;
const int _ifreqSize = 40;
const int _ifrFlagsOffset = 16;
const int _tunsetiff = 0x400454CA;
const int _iffTun = 0x0001;
const int _iffNoPi = 0x1000;

/// Linux TUN backend: creates a /dev/net/tun interface via ioctl, configures it
/// and installs routing with the `ip` command, and shuttles raw IP packets over
/// a dedicated reader isolate (inbound) and direct writes (outbound).
class LinuxTunBackend implements TunnelBackend {
  final Logger log;
  final Libc _libc = Libc();

  int _fd = -1;
  String _ifName = 'tun0';

  // Reverse operations to undo on close(), applied in LIFO order. Each entry is
  // a command's argument list plus a human label.
  final List<_Undo> _undo = [];

  final _inbound = StreamController<Uint8List>.broadcast();
  TunReader? _reader;

  // Reusable native scratch buffer for outbound writes.
  Pointer<Uint8>? _writeBuf;
  int _writeBufSize = 0;

  bool _closed = false;

  /// Called with what is left to undo after every change, so the tunnel can be
  /// taken down even if this isolate is killed. See [TeardownPlan].
  final void Function(TeardownPlan plan)? onTeardownPlan;

  LinuxTunBackend({required this.log, this.onTeardownPlan});

  @override
  String get interfaceName => _ifName;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Future<void> open(TunnelConfig config) async {
    _ifName = config.interfaceName;
    _createDevice(_ifName);
    _publishPlan();
    log.info('TUN', 'created interface $_ifName (fd=$_fd)');

    // Start the reader before routing so no inbound packet is missed.
    _reader = TunReader(
      fd: _fd,
      bufSize: config.mtu + 128,
      onPacket: _inbound.add,
      log: log,
    );
    await _reader!.start();

    try {
      await _configureInterface(config);
      await _installRouting(config);
    } catch (_) {
      await close();
      rethrow;
    }
    log.info('TUN', 'interface up and routing installed (${config.routeMode.name}-tunnel)');
  }

  void _createDevice(String name) {
    final pathPtr = '/dev/net/tun'.toNativeUtf8();
    try {
      _fd = _libc.open(pathPtr, oRdwr);
      if (_fd < 0) {
        final e = _libc.errno;
        throw TunnelException(
            'open(/dev/net/tun) failed (errno=$e). Is the tun module loaded?');
      }
    } finally {
      malloc.free(pathPtr);
    }

    final ifreq = calloc<Uint8>(_ifreqSize);
    try {
      // ifr_name at offset 0 (NUL-terminated, <= 15 chars).
      final nameBytes = name.codeUnits;
      if (nameBytes.length >= _ifnamsiz) {
        throw TunnelException('interface name "$name" too long');
      }
      final view = ifreq.asTypedList(_ifreqSize);
      for (var i = 0; i < nameBytes.length; i++) {
        view[i] = nameBytes[i];
      }
      // ifr_flags (short) at offset 16, host byte order.
      final flags = _iffTun | _iffNoPi;
      view[_ifrFlagsOffset] = flags & 0xff;
      view[_ifrFlagsOffset + 1] = (flags >> 8) & 0xff;

      final rc = _libc.ioctl(_fd, _tunsetiff, ifreq.cast<Void>());
      if (rc < 0) {
        final e = _libc.errno;
        _libc.close(_fd);
        _fd = -1;
        if (e == eperm) {
          throw TunnelPermissionException(
              'TUNSETIFF denied (EPERM): creating a TUN interface needs '
              'CAP_NET_ADMIN. Re-run under sudo.');
        }
        throw TunnelException('TUNSETIFF ioctl failed (errno=$e)');
      }
      // The kernel writes the actual name back into ifr_name.
      final end = view.indexOf(0);
      _ifName = String.fromCharCodes(view.sublist(0, end < 0 ? _ifnamsiz : end));
    } finally {
      calloc.free(ifreq);
    }
  }

  Future<void> _configureInterface(TunnelConfig config) async {
    // Address: a /32 on the tun; routes below are point-to-point via the device.
    await _ip(['addr', 'add', '${config.assignedIp}/32', 'dev', _ifName],
        undo: ['addr', 'del', '${config.assignedIp}/32', 'dev', _ifName],
        label: 'assign ${config.assignedIp}');
    await _ip(['link', 'set', _ifName, 'mtu', '${config.mtu}'],
        label: 'set mtu ${config.mtu}'); // no undo: iface is removed on close
    await _ip(['link', 'set', _ifName, 'up'],
        undo: ['link', 'set', _ifName, 'down'], label: 'bring up');
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
      log.debug('TUN', 'original default: via ${def.gateway} dev ${def.dev}');
      // replace, not add: a pin left by a session killed before its teardown
      // ("File exists") would otherwise fail every later connect to this server.
      await _ip(
        ['route', 'replace', '$serverIp/32', 'via', def.gateway, 'dev', def.dev],
        undo: ['route', 'del', '$serverIp/32'],
        label: 'pin server $serverIp via ${def.gateway}',
      );
      await _keepSshClientOutside();
      // Override the default with two /1 routes (does not delete 0.0.0.0/0).
      await _ip(['route', 'replace', '0.0.0.0/1', 'dev', _ifName],
          undo: ['route', 'del', '0.0.0.0/1', 'dev', _ifName],
          label: 'default half 0.0.0.0/1 via tunnel');
      await _ip(['route', 'replace', '128.0.0.0/1', 'dev', _ifName],
          undo: ['route', 'del', '128.0.0.0/1', 'dev', _ifName],
          label: 'default half 128.0.0.0/1 via tunnel');
      await _routeDnsThroughTunnel();
    } else {
      if (config.splitCidrs.isEmpty) {
        log.warn('TUN',
            'split-tunnel requested with no --route CIDRs; no traffic will use the tunnel');
      }
      for (final cidr in config.splitCidrs) {
        await _ip(['route', 'add', cidr, 'dev', _ifName],
            undo: ['route', 'del', cidr, 'dev', _ifName],
            label: 'split route $cidr via tunnel');
      }
    }
  }

  /// Points systemd-resolved at the tunnel. Traffic already flows without it,
  /// so a failure is warned about and never ends the connection.
  Future<void> _routeDnsThroughTunnel() async {
    var noPrompt = true;
    final steps = resolvectlSteps(_ifName);
    for (var i = 0; i < steps.length; i++) {
      log.debug('DNS', 'resolvectl ${steps[i].join(' ')}');
      final ProcessResult r;
      try {
        r = await Process.run('resolvectl', steps[i]);
      } on ProcessException {
        log.warn('DNS',
            'DNS is NOT going through the VPN: systemd-resolved is not installed.');
        return;
      }
      if (r.exitCode != 0) {
        final err = (r.stderr as String).trim();
        if (noPrompt && resolvectlLacksNoPrompt(err)) {
          noPrompt = false;
          steps.setAll(0, resolvectlSteps(_ifName, noPrompt: false));
          i--; // the same step again, without the flag
          continue;
        }
        log.warn('DNS', dnsFailureAdvice(err));
        return;
      }
    }
    _undo.add(_Undo(resolvectlRevert(_ifName, noPrompt: noPrompt),
        'restore DNS', command: 'resolvectl'));
    _publishPlan();
    log.info('DNS',
        'resolver set to ${linuxTunnelResolvers.join(', ')} via $_ifName');

    try {
      final warning = dnsBypassWarning(
          await File('/etc/resolv.conf').readAsString());
      if (warning != null) log.warn('DNS', warning);
    } on FileSystemException catch (e) {
      log.debug('DNS', 'could not read /etc/resolv.conf: ${e.message}');
    }
  }

  @override
  Future<void> writePacket(Uint8List packet) async {
    if (_fd < 0) return;
    final n = packet.length;
    if (_writeBuf == null || _writeBufSize < n) {
      if (_writeBuf != null) calloc.free(_writeBuf!);
      _writeBuf = calloc<Uint8>(n);
      _writeBufSize = n;
    }
    _writeBuf!.asTypedList(n).setAll(0, packet);
    final rc = _libc.write(_fd, _writeBuf!.cast<Void>(), n);
    if (rc < 0) {
      log.trace('TUN', 'write failed (errno=${_libc.errno})');
    }
  }

  @override
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    log.info('TUN', 'tearing down $_ifName');

    await _reader?.stop();

    // Revert routing/address changes in reverse order; tolerate failures. A
    // command leaves the plan only once it has run.
    while (_undo.isNotEmpty) {
      final u = _undo.last;
      final r = await Process.run(u.command, u.args);
      if (r.exitCode != 0) {
        log.debug('TUN',
            'undo "${u.label}" exited ${r.exitCode}: ${(r.stderr as String).trim()}');
      } else {
        log.debug('TUN', 'reverted: ${u.label}');
      }
      _undo.removeLast();
      _publishPlan();
    }

    // Closing the fd removes the (non-persistent) interface. It leaves the
    // plan in the same synchronous step, so a kill never leaves it named there
    // after it was closed (and possibly reused).
    if (_fd >= 0) {
      final fd = _fd;
      _fd = -1;
      _publishPlan();
      _libc.close(fd);
    }
    if (_writeBuf != null) {
      calloc.free(_writeBuf!);
      _writeBuf = null;
    }
    if (!_inbound.isClosed) await _inbound.close();
    log.info('TUN', 'teardown complete');
  }

  // -- helpers -------------------------------------------------------------

  Future<void> _ip(List<String> args,
      {List<String>? undo, required String label}) async {
    log.debug('TUN', 'ip ${args.join(' ')}');
    final r = await Process.run('ip', args);
    if (r.exitCode != 0) {
      final err = (r.stderr as String).trim();
      if (err.toLowerCase().contains('operation not permitted')) {
        throw TunnelPermissionException(
            'ip ${args.join(' ')} denied: needs CAP_NET_ADMIN/root. $err');
      }
      throw TunnelException('ip ${args.join(' ')} failed: $err');
    }
    if (undo != null) {
      _undo.add(_Undo(undo, label));
      _publishPlan();
    }
  }

  void _publishPlan() => onTeardownPlan?.call(TeardownPlan(
        commands: [
          for (final u in _undo) TeardownCommand(u.command, u.args, u.label),
        ],
        tunFd: _fd >= 0 ? _fd : null,
      ));

  Future<_DefaultRoute?> _defaultRoute() async {
    final r = await Process.run('ip', ['-o', 'route', 'show', 'default']);
    if (r.exitCode != 0) return null;
    final line = (r.stdout as String).split('\n').firstWhere(
          (l) => l.trim().isNotEmpty,
          orElse: () => '',
        );
    if (line.isEmpty) return null;
    // e.g. "default via 192.168.1.1 dev wlp0s20f3 proto dhcp ..."
    final route = parseGatewayRoute(line);
    return route == null ? null : _DefaultRoute(route.gateway, route.dev);
  }

  /// Run over SSH, keeps the path to the SSH client as it is: the /1 routes
  /// would send the replies into the tunnel and freeze the session. A client
  /// on the local subnet needs nothing, its link route is more specific.
  Future<void> _keepSshClientOutside() async {
    final client = sshClientAddress(Platform.environment['SSH_CONNECTION']);
    if (client == null) return;
    final r = await Process.run('ip', ['-o', 'route', 'get', client]);
    final route = r.exitCode == 0 ? parseGatewayRoute(r.stdout as String) : null;
    if (route == null) return;
    await _ip(
      ['route', 'replace', '$client/32', 'via', route.gateway, 'dev', route.dev],
      undo: ['route', 'del', '$client/32'],
      label: 'keep SSH client $client outside the tunnel',
    );
  }
}

class _Undo {
  final String command;
  final List<String> args;
  final String label;
  _Undo(this.args, this.label, {this.command = 'ip'});
}

class _DefaultRoute {
  final String gateway;
  final String dev;
  _DefaultRoute(this.gateway, this.dev);
}

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'libc.dart';
import 'logging.dart';
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
  // an `ip` argument list plus a human label.
  final List<_Undo> _undo = [];

  final _inbound = StreamController<Uint8List>.broadcast();
  TunReader? _reader;

  // Reusable native scratch buffer for outbound writes.
  Pointer<Uint8>? _writeBuf;
  int _writeBufSize = 0;

  bool _closed = false;

  LinuxTunBackend({required this.log});

  @override
  String get interfaceName => _ifName;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Future<void> open(TunnelConfig config) async {
    _ifName = config.interfaceName;
    _createDevice(_ifName);
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
      await _ip(
        ['route', 'add', '$serverIp/32', 'via', def.gateway, 'dev', def.dev],
        undo: ['route', 'del', '$serverIp/32'],
        label: 'pin server $serverIp via ${def.gateway}',
      );
      // Override the default with two /1 routes (does not delete 0.0.0.0/0).
      await _ip(['route', 'add', '0.0.0.0/1', 'dev', _ifName],
          undo: ['route', 'del', '0.0.0.0/1', 'dev', _ifName],
          label: 'default half 0.0.0.0/1 via tunnel');
      await _ip(['route', 'add', '128.0.0.0/1', 'dev', _ifName],
          undo: ['route', 'del', '128.0.0.0/1', 'dev', _ifName],
          label: 'default half 128.0.0.0/1 via tunnel');
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

    // Revert routing/address changes in reverse order; tolerate failures.
    for (final u in _undo.reversed) {
      final r = await Process.run('ip', u.args);
      if (r.exitCode != 0) {
        log.debug('TUN',
            'undo "${u.label}" exited ${r.exitCode}: ${(r.stderr as String).trim()}');
      } else {
        log.debug('TUN', 'reverted: ${u.label}');
      }
    }
    _undo.clear();

    // Closing the fd removes the (non-persistent) interface.
    if (_fd >= 0) {
      _libc.close(_fd);
      _fd = -1;
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
    if (undo != null) _undo.add(_Undo(undo, label));
  }

  Future<_DefaultRoute?> _defaultRoute() async {
    final r = await Process.run('ip', ['-o', 'route', 'show', 'default']);
    if (r.exitCode != 0) return null;
    final line = (r.stdout as String).split('\n').firstWhere(
          (l) => l.trim().isNotEmpty,
          orElse: () => '',
        );
    if (line.isEmpty) return null;
    // e.g. "default via 192.168.1.1 dev wlp0s20f3 proto dhcp ..."
    final tokens = line.split(RegExp(r'\s+'));
    String? gw, dev;
    for (var i = 0; i < tokens.length - 1; i++) {
      if (tokens[i] == 'via') gw = tokens[i + 1];
      if (tokens[i] == 'dev') dev = tokens[i + 1];
    }
    if (gw == null || dev == null) return null;
    return _DefaultRoute(gw, dev);
  }
}

class _Undo {
  final List<String> args;
  final String label;
  _Undo(this.args, this.label);
}

class _DefaultRoute {
  final String gateway;
  final String dev;
  _DefaultRoute(this.gateway, this.dev);
}

import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'libc.dart';
import 'logging.dart';
import 'tun_reader.dart';
import 'tunnel_backend.dart';

// Constants verified against Apple's XNU headers (bsd/sys/kern_control.h,
// bsd/net/if_utun.h, bsd/sys/sys_domain.h, bsd/sys/socket.h):
//
//   struct ctl_info    { u_int32_t ctl_id; char ctl_name[96]; }        = 100 B
//   struct sockaddr_ctl{ u_char sc_len; u_char sc_family;              =  32 B
//                        u_int16_t ss_sysaddr; u_int32_t sc_id;
//                        u_int32_t sc_unit; u_int32_t sc_reserved[5]; }
//   CTLIOCGINFO = _IOWR('N', 3, struct ctl_info)
//               = 0xC0000000 | (100<<16) | ('N'<<8) | 3 = 0xC0644E03
const int _pfSystem = 32; // PF_SYSTEM
const int _sockDgram = 2; // SOCK_DGRAM
const int _sysprotoControl = 2; // SYSPROTO_CONTROL
const int _afSysControl = 2; // AF_SYS_CONTROL (sockaddr_ctl.ss_sysaddr)
const int _ctliocginfo = 0xC0644E03;
const int _utunOptIfname = 2; // UTUN_OPT_IFNAME
const String _utunControlName = 'com.apple.net.utun_control';

const int _ctlInfoSize = 100;
const int _ctlNameOffset = 4;
const int _sockaddrCtlSize = 32;

// Darwin address families. NOTE: AF_INET6 is 30 on Darwin, not 10 as on Linux.
const int afInet = 2;
const int afInet6 = 30;

/// Every packet read from / written to a utun fd is prefixed with a 4-byte
/// address family in network byte order. This is the key difference from
/// Linux's `IFF_NO_PI` TUN, which carries raw IP with no prefix.
const int utunPrefixLen = 4;

/// The address family to put in a packet's utun prefix, from its IP version
/// nibble. Darwin's [afInet6] is 30 — using Linux's 10 here would make the
/// kernel silently misinterpret every IPv6 packet.
int utunAddressFamily(Uint8List packet) =>
    (packet.isNotEmpty && (packet[0] >> 4) == 6) ? afInet6 : afInet;

/// macOS utun backend: creates a utun interface by connecting a PF_SYSTEM
/// kernel-control socket, shuttles raw IP packets over it (inbound via the same
/// poll()-based reader isolate the Linux backend uses), and configures the
/// address, MTU and routing with `ifconfig`/`route`.
///
/// The third implementation of [TunnelBackend], alongside `LinuxTunBackend` and
/// `WindowsTunBackend`. Requires root (`sudo`).
class MacosUtunBackend implements TunnelBackend {
  final Logger log;
  final Libc _libc = Libc();

  int _fd = -1;
  String _ifName = '';

  // Reverse operations to undo on close(), applied in LIFO order.
  final List<_Undo> _undo = [];

  final _inbound = StreamController<Uint8List>.broadcast();
  TunReader? _reader;

  // Reusable native scratch buffer for outbound writes (AF prefix + packet).
  Pointer<Uint8>? _writeBuf;
  int _writeBufSize = 0;

  bool _closed = false;

  MacosUtunBackend({required this.log});

  @override
  String get interfaceName => _ifName;

  @override
  Stream<Uint8List> get inbound => _inbound.stream;

  @override
  Future<void> open(TunnelConfig config) async {
    _createDevice(config.interfaceName);
    log.info('TUN', 'created interface $_ifName (fd=$_fd)');

    // Start the reader before routing so no inbound packet is missed. The utun
    // fd hands us [4-byte AF][IP packet]; strip the prefix before publishing.
    _reader = TunReader(
      fd: _fd,
      bufSize: config.mtu + 128,
      onPacket: (frame) {
        if (frame.length > utunPrefixLen) {
          _inbound.add(Uint8List.sublistView(frame, utunPrefixLen));
        }
      },
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
    log.info('TUN',
        'interface up and routing installed (${config.routeMode.name}-tunnel)');
  }

  /// Opens a kernel-control socket to `com.apple.net.utun_control` and connects
  /// it, which is what actually creates the utun interface.
  ///
  /// [requested] may name a specific unit (e.g. "utun7"); anything else lets the
  /// kernel pick the first free unit (sc_unit = 0).
  void _createDevice(String requested) {
    _fd = _libc.socket(_pfSystem, _sockDgram, _sysprotoControl);
    if (_fd < 0) {
      final e = _libc.errno;
      throw TunnelException(
          'socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) failed (errno=$e)');
    }

    // 1. Resolve the utun control id by name: ioctl(CTLIOCGINFO, &ctl_info).
    final ctlInfo = calloc<Uint8>(_ctlInfoSize);
    final int ctlId;
    try {
      final view = ctlInfo.asTypedList(_ctlInfoSize);
      final nameBytes = _utunControlName.codeUnits;
      for (var i = 0; i < nameBytes.length; i++) {
        view[_ctlNameOffset + i] = nameBytes[i]; // ctl_name, NUL-padded
      }
      if (_libc.ioctl(_fd, _ctliocginfo, ctlInfo.cast<Void>()) < 0) {
        final e = _libc.errno;
        _libc.close(_fd);
        _fd = -1;
        throw TunnelException(
            'ioctl(CTLIOCGINFO) failed (errno=$e): could not resolve '
            '$_utunControlName');
      }
      ctlId = ctlInfo.cast<Uint32>().value; // ctl_id @0
    } finally {
      calloc.free(ctlInfo);
    }

    // 2. connect() the sockaddr_ctl — this creates the interface.
    //    sc_unit is the utun number + 1; 0 means "first available".
    final unit = _unitFor(requested);
    final addr = calloc<Uint8>(_sockaddrCtlSize);
    try {
      final view = addr.asTypedList(_sockaddrCtlSize);
      view[0] = _sockaddrCtlSize; // sc_len
      view[1] = _pfSystem; // sc_family (AF_SYSTEM)
      final words = addr.cast<Uint16>();
      words[1] = _afSysControl; // ss_sysaddr @2 (host byte order)
      final dwords = addr.cast<Uint32>();
      dwords[1] = ctlId; // sc_id   @4
      dwords[2] = unit; // sc_unit @8

      if (_libc.connect(_fd, addr.cast<Void>(), _sockaddrCtlSize) < 0) {
        final e = _libc.errno;
        _libc.close(_fd);
        _fd = -1;
        if (e == eperm) {
          throw TunnelPermissionException(
              'connect(utun control) denied (EPERM): creating a utun interface '
              'needs root. Re-run under sudo.');
        }
        throw TunnelException('connect(utun control) failed (errno=$e)');
      }
    } finally {
      calloc.free(addr);
    }

    // 3. Ask the kernel which utun it actually gave us.
    _ifName = _readIfName();
  }

  /// "utun7" -> sc_unit 8; anything else (including the default "tun0") -> 0,
  /// letting the kernel pick. macOS interfaces are always named utunN, so a
  /// Linux-style name cannot be honoured.
  int _unitFor(String requested) {
    final m = RegExp(r'^utun(\d+)$').firstMatch(requested);
    if (m == null) {
      log.debug('TUN',
          'interface name "$requested" is not a utunN name; letting the kernel '
          'choose');
      return 0;
    }
    return int.parse(m.group(1)!) + 1;
  }

  String _readIfName() {
    const bufLen = 32;
    final buf = calloc<Uint8>(bufLen);
    final lenPtr = calloc<Uint32>()..value = bufLen;
    try {
      final rc = _libc.getsockopt(
          _fd, _sysprotoControl, _utunOptIfname, buf.cast<Void>(), lenPtr);
      if (rc < 0) {
        throw TunnelException(
            'getsockopt(UTUN_OPT_IFNAME) failed (errno=${_libc.errno})');
      }
      final view = buf.asTypedList(lenPtr.value);
      final end = view.indexOf(0);
      return String.fromCharCodes(
          end < 0 ? view : view.sublist(0, end));
    } finally {
      calloc.free(buf);
      calloc.free(lenPtr);
    }
  }

  Future<void> _configureInterface(TunnelConfig config) async {
    // utun is point-to-point: local and destination are both the assigned IP.
    // The interface disappears when the fd closes, so no undo is needed here.
    await _run(
      'ifconfig',
      [_ifName, 'inet', config.assignedIp, config.assignedIp, 'netmask',
        '255.255.255.255', 'up'],
      label: 'assign ${config.assignedIp}',
    );
    await _run('ifconfig', [_ifName, 'mtu', '${config.mtu}'],
        label: 'set mtu ${config.mtu}');
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
      await _run(
        'route',
        ['add', '-host', serverIp, def.gateway],
        undo: _Cmd('route', ['delete', '-host', serverIp]),
        label: 'pin server $serverIp via ${def.gateway}',
      );
      // Override the default with two /1 routes (never deletes the real
      // 0.0.0.0/0, so revert is just removing what we added).
      await _addTunnelRoute('0.0.0.0/1', 'default half 0.0.0.0/1 via tunnel');
      await _addTunnelRoute(
          '128.0.0.0/1', 'default half 128.0.0.0/1 via tunnel');
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

  Future<void> _addTunnelRoute(String cidr, String label) async {
    await _run(
      'route',
      ['add', '-net', cidr, '-interface', _ifName],
      undo: _Cmd('route', ['delete', '-net', cidr, '-interface', _ifName]),
      label: label,
    );
  }

  @override
  Future<void> writePacket(Uint8List packet) async {
    if (_fd < 0 || packet.isEmpty) return;
    final af = utunAddressFamily(packet);
    final n = utunPrefixLen + packet.length;
    if (_writeBuf == null || _writeBufSize < n) {
      if (_writeBuf != null) calloc.free(_writeBuf!);
      _writeBuf = calloc<Uint8>(n);
      _writeBufSize = n;
    }
    final view = _writeBuf!.asTypedList(n);
    // 4-byte address family, network byte order.
    view[0] = (af >> 24) & 0xff;
    view[1] = (af >> 16) & 0xff;
    view[2] = (af >> 8) & 0xff;
    view[3] = af & 0xff;
    view.setAll(utunPrefixLen, packet);

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

    // Revert routing in reverse order; tolerate failures.
    for (final u in _undo.reversed) {
      final r = await Process.run(u.exe, u.args);
      if (r.exitCode != 0) {
        log.debug('TUN',
            'undo "${u.label}" exited ${r.exitCode}: ${(r.stderr as String).trim()}');
      } else {
        log.debug('TUN', 'reverted: ${u.label}');
      }
    }
    _undo.clear();

    // Closing the control socket destroys the utun interface.
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

  Future<void> _run(String exe, List<String> args,
      {_Cmd? undo, required String label}) async {
    log.debug('TUN', '$exe ${args.join(' ')}');
    final r = await Process.run(exe, args);
    if (r.exitCode != 0) {
      final err = (r.stderr as String).trim();
      final l = err.toLowerCase();
      if (l.contains('not owner') ||
          l.contains('permission denied') ||
          l.contains('operation not permitted')) {
        throw TunnelPermissionException(
            '$exe ${args.join(' ')} denied: needs root. Re-run under sudo. $err');
      }
      throw TunnelException('$exe ${args.join(' ')} failed: $err');
    }
    if (undo != null) _undo.add(_Undo(undo.exe, undo.args, label));
  }

  Future<MacosDefaultRoute?> _defaultRoute() async {
    final r = await Process.run('route', ['-n', 'get', 'default']);
    if (r.exitCode != 0) return null;
    return parseMacosDefaultRoute(r.stdout as String);
  }
}

/// Parses `route -n get default` output, which looks like:
///
///        route to: default
///     destination: default
///            mask: default
///         gateway: 192.168.1.1
///       interface: en0
///
/// Returns null if no gateway is present (e.g. no default route).
MacosDefaultRoute? parseMacosDefaultRoute(String routeOutput) {
  String? gw, dev;
  for (final line in routeOutput.split('\n')) {
    final i = line.indexOf(':');
    if (i < 0) continue;
    final key = line.substring(0, i).trim();
    final value = line.substring(i + 1).trim();
    if (key == 'gateway') gw = value;
    if (key == 'interface') dev = value;
  }
  if (gw == null || dev == null) return null;
  return MacosDefaultRoute(gw, dev);
}

class MacosDefaultRoute {
  final String gateway;
  final String dev;
  MacosDefaultRoute(this.gateway, this.dev);
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

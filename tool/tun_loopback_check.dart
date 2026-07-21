/// Device-level check for the TUN backends. Requires root.
///
/// Unlike the unit tests, this exercises the real kernel device end to end
/// without needing a VPN server:
///
///   1. Open the TUN/utun interface, assign an address, and route a dummy
///      prefix into it (split mode, so the host's default route is untouched).
///   2. `ping` an address inside that prefix. The kernel pushes a real ICMP
///      echo request into the interface.
///   3. The backend's reader must deliver that packet to us  -> proves device
///      creation, the FFI struct/ioctl layouts, and (on macOS) stripping utun's
///      4-byte address-family prefix.
///   4. We answer with a crafted ICMP echo reply via writePacket()  -> proves
///      the write path and (on macOS) prepending the AF prefix.
///   5. If ping reports success, every layer worked against the real kernel.
///   6. close() must remove the interface and revert the route.
///
/// Exits 0 on success, non-zero with a diagnosis on failure. Run under sudo:
///
///     dart compile exe tool/tun_loopback_check.dart -o tun_check
///     sudo ./tun_check
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:sstp_client/sstp_client.dart';

const _localIp = '10.9.9.1';
const _testCidr = '10.99.0.0/16';
const _pingTarget = '10.99.0.1';

Future<void> main() async {
  final log = Logger(level: LogLevel.debug);

  if (!Platform.isLinux && !Platform.isMacOS) {
    stderr.writeln('This check only runs on Linux or macOS.');
    exit(2);
  }

  final backend = Platform.isMacOS
      ? MacosUtunBackend(log: log)
      : LinuxTunBackend(log: log);

  final config = TunnelConfig(
    assignedIp: _localIp,
    // Unused in split mode (no server route is pinned); TEST-NET-1 placeholder.
    serverAddress: InternetAddress('192.0.2.1'),
    mtu: 1400,
    routeMode: RouteMode.split,
    splitCidrs: const [_testCidr],
    interfaceName: Platform.isMacOS ? 'utun' : 'tun9',
  );

  var echoRequests = 0;
  var repliesSent = 0;

  try {
    await backend.open(config);
    print('--- interface ${backend.interfaceName} is up ---');

    backend.inbound.listen((packet) {
      final reply = _buildIcmpEchoReply(packet);
      if (reply == null) return; // not an ICMP echo request we handle
      echoRequests++;
      repliesSent++;
      backend.writePacket(reply);
    });

    // Give the reader isolate a moment to be listening.
    await Future<void>.delayed(const Duration(milliseconds: 500));

    print('--- pinging $_pingTarget through ${backend.interfaceName} ---');
    final ping = await Process.run('ping', _pingArgs());
    stdout.write(ping.stdout);
    if ((ping.stderr as String).trim().isNotEmpty) {
      stderr.write(ping.stderr);
    }

    // Let any in-flight reply settle before tearing down.
    await Future<void>.delayed(const Duration(milliseconds: 300));

    print('');
    print('  ICMP echo requests received from kernel : $echoRequests');
    print('  ICMP echo replies written to device     : $repliesSent');
    print('  ping exit code                          : ${ping.exitCode}');

    if (echoRequests == 0) {
      _fail('No packet ever arrived from the kernel. The device was created '
          'but the read path is broken (reader isolate, or on macOS the '
          '4-byte AF prefix handling).');
    }
    if (ping.exitCode != 0) {
      _fail('Packets arrived from the kernel, but ping never saw our replies. '
          'The read path works; the WRITE path is broken (on macOS, most '
          'likely the AF prefix we prepend).');
    }

    print('');
    print('RESULT: ✓ round trip through the real device succeeded');
  } catch (e) {
    if (e is TunnelPermissionException) {
      _fail('Needs root: $e');
    }
    _fail('$e');
  } finally {
    await backend.close();
  }

  // Teardown must leave nothing behind.
  final leftovers = await _leftovers(backend.interfaceName);
  if (leftovers.isNotEmpty) {
    _fail('Teardown left state behind:\n  ${leftovers.join("\n  ")}');
  }
  print('RESULT: ✓ teardown reverted the interface and the route');
  exit(0);
}

Never _fail(String why) {
  stderr.writeln('');
  stderr.writeln('RESULT: ✗ $why');
  exit(1);
}

List<String> _pingArgs() => Platform.isMacOS
    // macOS: -t is a total timeout in seconds, -S sets the source address.
    ? ['-c', '3', '-t', '5', '-S', _localIp, _pingTarget]
    // Linux: -t is TTL; -w is the deadline, -I selects the source.
    : ['-c', '3', '-w', '5', '-I', _localIp, _pingTarget];

/// Confirms close() removed both the interface and the route it added.
Future<List<String>> _leftovers(String ifName) async {
  final problems = <String>[];

  final links = await Process.run(
      Platform.isMacOS ? 'ifconfig' : 'ip', Platform.isMacOS ? ['-a'] : ['link']);
  if ((links.stdout as String).contains(ifName)) {
    problems.add('interface $ifName still exists');
  }

  final routes = await Process.run(
      Platform.isMacOS ? 'netstat' : 'ip',
      Platform.isMacOS ? ['-rn', '-f', 'inet'] : ['route', 'show']);
  if ((routes.stdout as String).contains('10.99')) {
    problems.add('route $_testCidr was not reverted');
  }
  return problems;
}

/// Turns an ICMP echo request into its echo reply: swap source/destination,
/// set type 0, and recompute the ICMP checksum. Returns null if [packet] is not
/// an IPv4 ICMP echo request.
///
/// The IPv4 header checksum is left alone on purpose: swapping two 16-bit
/// aligned fields does not change a one's-complement sum.
Uint8List? _buildIcmpEchoReply(Uint8List packet) {
  if (packet.length < 20) return null;
  if ((packet[0] >> 4) != 4) return null; // not IPv4
  final ihl = (packet[0] & 0x0f) * 4;
  if (packet.length < ihl + 8) return null;
  if (packet[9] != 1) return null; // not ICMP
  if (packet[ihl] != 8) return null; // not an echo request

  final reply = Uint8List.fromList(packet);

  // Swap src (12..16) and dst (16..20).
  for (var i = 0; i < 4; i++) {
    final tmp = reply[12 + i];
    reply[12 + i] = reply[16 + i];
    reply[16 + i] = tmp;
  }

  reply[ihl] = 0; // ICMP type: echo reply
  reply[ihl + 2] = 0; // zero the checksum before recomputing
  reply[ihl + 3] = 0;
  final sum = _checksum16(reply, ihl, reply.length);
  reply[ihl + 2] = (sum >> 8) & 0xff;
  reply[ihl + 3] = sum & 0xff;
  return reply;
}

/// Standard 16-bit one's-complement checksum over [start, end).
int _checksum16(Uint8List data, int start, int end) {
  var sum = 0;
  var i = start;
  while (i + 1 < end) {
    sum += (data[i] << 8) | data[i + 1];
    i += 2;
  }
  if (i < end) sum += data[i] << 8; // odd trailing byte
  while (sum >> 16 != 0) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  return ~sum & 0xffff;
}

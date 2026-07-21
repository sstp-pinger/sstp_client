import 'dart:async';
import 'dart:io';

import 'package:args/args.dart';
import 'package:sstp_client/sstp_client.dart';

Future<void> main(List<String> argv) async {
  final parser = ArgParser()
    ..addOption('host', help: 'SSTP server hostname or IP (required)')
    ..addOption('port', defaultsTo: '443', help: 'SSTP server port')
    ..addOption('username', help: 'VPN username (required)')
    ..addOption('password', help: 'VPN password (required)')
    ..addFlag('verify-cert',
        defaultsTo: false,
        help: 'Reject untrusted server certificates (VPN Gate servers are '
            'usually self-signed, so this is off by default)')
    ..addFlag('tunnel',
        defaultsTo: false,
        help: 'After the handshake, bring up a TUN device and route traffic '
            '(Linux: root/CAP_NET_ADMIN; Windows: Administrator + wintun.dll)')
    ..addOption('route-mode',
        defaultsTo: 'full',
        allowed: ['full', 'split'],
        help: 'full = all traffic via tunnel; split = only --route CIDRs')
    ..addMultiOption('route',
        help: 'Split-tunnel destination CIDR (repeatable), e.g. 10.0.0.0/8')
    ..addOption('iface', defaultsTo: 'tun0', help: 'TUN interface name')
    ..addOption('mtu', defaultsTo: '1400', help: 'TUN interface MTU')
    ..addOption('duration',
        help: 'Seconds to keep the tunnel up before auto-teardown '
            '(default: run until Ctrl+C)')
    ..addFlag('test',
        defaultsTo: false,
        help: 'Run a before/after egress-IP check to prove traffic flows')
    ..addFlag('verbose',
        abbr: 'v', defaultsTo: false, help: 'Enable debug/trace logging')
    ..addFlag('help', abbr: 'h', negatable: false);

  final ArgResults args;
  try {
    args = parser.parse(argv);
  } on FormatException catch (e) {
    stderr.writeln(e.message);
    stderr.writeln(parser.usage);
    exit(2);
  }

  if (args['help'] as bool) {
    print('SSTP client test harness (TUN tunneling on Linux and Windows)\n');
    print(parser.usage);
    return;
  }

  final host = args['host'] as String?;
  final username = args['username'] as String?;
  final password = args['password'] as String?;
  final missing = <String>[
    if (host == null) 'host',
    if (username == null) 'username',
    if (password == null) 'password',
  ];
  if (missing.isNotEmpty) {
    stderr.writeln('Missing required option(s): ${missing.join(", ")}\n');
    stderr.writeln(parser.usage);
    exit(2);
  }

  final port = int.tryParse(args['port'] as String);
  if (port == null || port < 1 || port > 65535) {
    stderr.writeln('Invalid port: ${args['port']}');
    exit(2);
  }
  final mtu = int.tryParse(args['mtu'] as String) ?? 1400;

  final verbose = args['verbose'] as bool;
  final log = Logger(level: verbose ? LogLevel.trace : LogLevel.info);
  final wantTunnel = args['tunnel'] as bool;

  if (wantTunnel &&
      !(Platform.isLinux || Platform.isWindows || Platform.isMacOS)) {
    stderr.writeln('--tunnel is only implemented for Linux, Windows and macOS.');
    exit(2);
  }

  log.info('MAIN', 'Target $host:$port as user "$username"');
  final session = SstpSession(
    host: host!,
    port: port,
    userName: username!,
    password: password!,
    log: log,
    verifyCertificate: args['verify-cert'] as bool,
  );

  TunnelBackend? backend;
  var tornDown = false;

  Future<void> teardown() async {
    if (tornDown) return;
    tornDown = true;
    try {
      await backend?.close();
    } catch (e) {
      log.warn('MAIN', 'tunnel teardown error: $e');
    }
    await session.close();
  }

  // Ensure clean teardown on Ctrl+C / SIGTERM. Windows only supports SIGINT;
  // watching SIGTERM there throws "The request is not supported".
  final signals = <StreamSubscription>[];
  final watched = [
    ProcessSignal.sigint,
    if (!Platform.isWindows) ProcessSignal.sigterm,
  ];
  for (final sig in watched) {
    signals.add(sig.watch().listen((_) async {
      log.info('MAIN', 'signal received, disconnecting...');
      await teardown();
      exit(130);
    }));
  }

  try {
    final result = await session.run();
    print('');
    print('==================== HANDSHAKE OK ===============');
    print(' Assigned tunnel IP : ${result.assignedIp}');
    if (result.dns != null) print(' DNS server         : ${result.dns}');
    print(' Negotiated MRU     : ${result.mru}');
    print('=================================================');

    if (!wantTunnel) {
      await teardown();
      exit(0);
    }

    // ---- Milestone 2: bring up the TUN device and routing ----
    final serverAddr = session.serverAddress;
    if (serverAddr == null) {
      throw StateError('server address unavailable; cannot pin route');
    }

    String? egressBefore;
    if (args['test'] as bool) {
      egressBefore = await _egressIp(log);
      log.info('TEST', 'egress IP before tunnel: ${egressBefore ?? "unknown"}');
    }

    final routeMode =
        (args['route-mode'] as String) == 'split' ? RouteMode.split : RouteMode.full;
    backend = switch (Platform.operatingSystem) {
      'windows' => WindowsTunBackend(log: log),
      'macos' => MacosUtunBackend(log: log),
      _ => LinuxTunBackend(log: log),
    };
    final config = TunnelConfig(
      assignedIp: result.assignedIp,
      serverAddress: serverAddr,
      mtu: mtu,
      routeMode: routeMode,
      splitCidrs: args['route'] as List<String>,
      dns: result.dns,
      interfaceName: args['iface'] as String,
    );
    await backend.open(config);

    // Wire the data plane both directions. Only IPv4 goes out: we negotiated
    // IPCP only, so forwarding the IPv6 the OS puts on a fresh interface (router
    // solicitations, MLD) just earns a Protocol-Reject per packet from the
    // server.
    final s1 = session.inboundPackets.listen(backend.writePacket);
    final s2 = backend.inbound.listen((pkt) {
      if (pkt.isNotEmpty && (pkt[0] >> 4) == 4) session.sendPacket(pkt);
    });

    print('');
    print('==================== TUNNEL UP ==================');
    print(' Interface          : ${backend.interfaceName}');
    print(' Mode               : ${routeMode.name}-tunnel');
    print(' Tunnel IP          : ${result.assignedIp}/32  (mtu $mtu)');
    print('=================================================');

    if (args['test'] as bool) {
      // Give the OS a moment to settle the new interface/routes, then re-check
      // the egress IP. Retried: the first probe after bring-up can still race
      // the stack (on Windows the address is briefly unusable), and a lone
      // failed probe would report a false negative.
      String? egressAfter;
      for (var attempt = 1; attempt <= 3 && egressAfter == null; attempt++) {
        await Future<void>.delayed(const Duration(seconds: 3));
        egressAfter = await _egressIp(log);
        if (egressAfter == null) {
          log.debug('TEST', 'egress probe $attempt failed; retrying');
        }
      }
      print('');
      print(' Egress IP before   : ${egressBefore ?? "unknown"}');
      print(' Egress IP via VPN  : ${egressAfter ?? "unknown"}');
      if (egressAfter != null && egressAfter != egressBefore) {
        print(' RESULT             : ✓ traffic is flowing through the tunnel');
      } else {
        print(' RESULT             : ✗ egress IP did not change — check routing');
      }
      print('=================================================');
    }

    final durationStr = args['duration'] as String?;
    if (durationStr != null) {
      final secs = int.tryParse(durationStr) ?? 0;
      log.info('MAIN', 'holding tunnel for ${secs}s then tearing down');
      await Future<void>.delayed(Duration(seconds: secs));
      await s1.cancel();
      await s2.cancel();
      await teardown();
      for (final s in signals) {
        await s.cancel();
      }
      exit(0);
    } else {
      log.info('MAIN', 'tunnel is up — press Ctrl+C to disconnect');
      // Stay alive until a signal triggers teardown.
      await Completer<void>().future;
    }
  } catch (e, st) {
    log.error('MAIN', 'failed: $e');
    if (verbose) log.error('MAIN', st.toString());
    await teardown();
    exit(1);
  }
}

/// Fetches the externally-visible egress IP without needing DNS (uses
/// Cloudflare's anycast 1.1.1.1 trace endpoint by IP literal).
Future<String?> _egressIp(Logger log) async {
  try {
    final r = await Process.run('curl', [
      '-s',
      '--max-time',
      '15',
      'https://1.1.1.1/cdn-cgi/trace',
    ]);
    if (r.exitCode != 0) {
      log.debug('TEST', 'curl exit ${r.exitCode}: ${(r.stderr as String).trim()}');
      return null;
    }
    for (final line in (r.stdout as String).split('\n')) {
      if (line.startsWith('ip=')) return line.substring(3).trim();
    }
    return null;
  } catch (e) {
    log.debug('TEST', 'egress check failed: $e');
    return null;
  }
}

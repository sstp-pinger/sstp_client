import 'dart:io';
import 'package:sstp_client/sstp_client.dart';

// Manual probe: exercises the FFI TUN device-creation path. As an unprivileged
// user it must raise TunnelPermissionException cleanly (not crash). Run under
// sudo and it will actually create/tear down the interface.
Future<void> main() async {
  final log = Logger(level: LogLevel.debug);
  final backend = LinuxTunBackend(log: log);
  try {
    await backend.open(TunnelConfig(
      assignedIp: '10.0.0.2',
      serverAddress: InternetAddress('203.0.113.1'),
      routeMode: RouteMode.split, // no default-route changes for the probe
      splitCidrs: const [],
    ));
    print('open() succeeded (running privileged); tearing down.');
    await backend.close();
  } on TunnelPermissionException catch (e) {
    print('GOT EXPECTED PERMISSION ERROR: ${e.message}');
  } catch (e) {
    print('OTHER ERROR (${e.runtimeType}): $e');
  }
}

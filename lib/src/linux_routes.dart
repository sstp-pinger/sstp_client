/// Reading `ip route` output on Linux. Pure, so it can be tested without a
/// network; [LinuxTunBackend] runs the commands.
library;

/// A route through a gateway: `via <gateway> dev <dev>`.
class LinuxGatewayRoute {
  final String gateway;
  final String dev;
  const LinuxGatewayRoute(this.gateway, this.dev);
}

/// The gateway and device in one line of `ip route show` or `ip route get`.
/// Null for an on-link route (no `via`), e.g. a host on the local subnet.
LinuxGatewayRoute? parseGatewayRoute(String line) {
  final tokens = line.trim().split(RegExp(r'\s+'));
  String? gw, dev;
  for (var i = 0; i < tokens.length - 1; i++) {
    if (tokens[i] == 'via') gw = tokens[i + 1];
    if (tokens[i] == 'dev') dev = tokens[i + 1];
  }
  if (gw == null || dev == null) return null;
  return LinuxGatewayRoute(gw, dev);
}

/// The IPv4 address of the SSH client this process runs under, from
/// `$SSH_CONNECTION` ("client_ip client_port server_ip server_port"). A full
/// tunnel would otherwise carry the replies to that client and freeze the
/// session that started it.
String? sshClientAddress(String? sshConnection) {
  final first = (sshConnection ?? '').trim().split(' ').first;
  final ok = RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(first) &&
      !first.startsWith('127.');
  return ok ? first : null;
}

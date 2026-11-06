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

/// Routing table (and rule priority) for replies sent from the LAN address,
/// see LinuxTunBackend. Any number no other tool uses; this one and the one
/// below it are taken.
const int replyRoutingTable = 7737;

/// The source address in one line of `ip route get`: the LAN address this
/// host uses toward that destination.
String? parseRouteSource(String line) {
  final tokens = line.trim().split(RegExp(r'\s+'));
  final at = tokens.indexOf('src');
  return at >= 0 && at + 1 < tokens.length ? tokens[at + 1] : null;
}

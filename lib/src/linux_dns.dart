/// What a full tunnel asks systemd-resolved to do on Linux. Pure, so it can be
/// tested without a resolver; [LinuxTunBackend] runs it.
library;

/// Public rather than the server's own: free relays often advertise a resolver
/// that doesn't answer, the same reason the Windows backend uses these.
const List<String> linuxTunnelResolvers = ['1.1.1.1', '8.8.8.8'];

/// Non-interactive, so a missing permission is an error to report instead of a
/// password dialog that blocks the connect. Older resolvectl (systemd 255, as
/// on Ubuntu 24.04) rejects it; see [resolvectlLacksNoPrompt].
const String resolvectlNoPrompt = '--no-ask-password';

/// The `resolvectl` calls that send all DNS through [ifName]. `~.` claims every
/// domain for the link, without it resolved keeps using the physical one too.
List<List<String>> resolvectlSteps(String ifName, {bool noPrompt = true}) => [
      for (final step in [
        ['dns', ifName, ...linuxTunnelResolvers],
        ['domain', ifName, '~.'],
        ['default-route', ifName, 'yes'],
      ])
        [if (noPrompt) resolvectlNoPrompt, ...step],
    ];

List<String> resolvectlRevert(String ifName, {bool noPrompt = true}) =>
    [if (noPrompt) resolvectlNoPrompt, 'revert', ifName];

/// Whether `resolvectl` failed only because it does not know
/// [resolvectlNoPrompt]; the calls are then made again without it.
bool resolvectlLacksNoPrompt(String error) =>
    error.contains('unrecognized option') && error.contains(resolvectlNoPrompt);

/// Why DNS is staying outside the tunnel, given what `resolvectl` printed.
String dnsFailureAdvice(String error) {
  final e = error.toLowerCase();
  if (e.contains('access denied') ||
      e.contains('permission denied') ||
      e.contains('interactive authentication') ||
      e.contains('not authorized')) {
    return 'DNS is NOT going through the VPN: this user may not change it. '
        'Installed from the .deb or Arch package: update to 3.7.2 or newer, '
        'and over SSH be in the sudo (or wheel) group. Tarball: run '
        'tool/setup_privilege.sh once more. Then reconnect.';
  }
  return 'DNS is NOT going through the VPN: systemd-resolved refused the '
      'change ($error).';
}

/// Warns when programs reading [resolvConf] skip systemd-resolved, so the
/// settings above would not reach them. Null when it is in the path.
String? dnsBypassWarning(String resolvConf) {
  final servers = [
    for (final line in resolvConf.split('\n'))
      if (RegExp(r'^\s*nameserver\s+(\S+)').firstMatch(line) case final m?)
        m.group(1)!,
  ];
  if (servers.any((s) => s == '127.0.0.53' || s == '127.0.0.54')) return null;
  final used = servers.isEmpty ? 'no nameserver' : servers.join(', ');
  final wsl = servers.contains('10.255.255.254')
      ? ' On WSL that is Windows answering: set generateResolvConf=false in '
          '/etc/wsl.conf and link /etc/resolv.conf to '
          '/run/systemd/resolve/stub-resolv.conf.'
      : '';
  return 'DNS may not go through the VPN: /etc/resolv.conf points at $used, '
      'not systemd-resolved.$wsl';
}

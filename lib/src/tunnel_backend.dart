import 'dart:io';
import 'dart:typed_data';

/// Whether to route all traffic through the tunnel or only selected prefixes.
enum RouteMode { full, split }

/// Everything a [TunnelBackend] needs to bring up a tunnel interface and its
/// routing. Platform-agnostic: the Windows/Wintun backend will consume the same
/// object.
class TunnelConfig {
  /// The tunnel IP assigned by IPCP (e.g. "10.234.195.107").
  final String assignedIp;

  /// Interface MTU. Kept below the physical MTU to leave room for SSTP/TLS/TCP
  /// encapsulation and avoid outer-path fragmentation.
  final int mtu;

  /// The real IP of the VPN server. A host route to this address via the
  /// original gateway keeps the encrypted SSTP transport on the physical link
  /// even under full-tunnel routing.
  final InternetAddress serverAddress;

  final RouteMode routeMode;

  /// For [RouteMode.split]: the destination prefixes to route through the
  /// tunnel (CIDR strings, e.g. "10.0.0.0/8"). Ignored for full-tunnel.
  final List<String> splitCidrs;

  /// IPCP-assigned DNS server, if any. The Windows backend applies it (adapter
  /// DNS + an NRPT catch-all) so lookups resolve through the tunnel instead of
  /// the physical/ISP resolver. Linux/macOS do not yet apply it.
  final String? dns;

  /// Desired interface name (e.g. "tun0"). The backend may adjust it if taken.
  final String interfaceName;

  TunnelConfig({
    required this.assignedIp,
    required this.serverAddress,
    this.mtu = 1400,
    this.routeMode = RouteMode.full,
    this.splitCidrs = const [],
    this.dns,
    this.interfaceName = 'tun0',
  });
}

/// Raised when tunnel setup fails for lack of privilege (CAP_NET_ADMIN / root).
class TunnelPermissionException implements Exception {
  final String message;
  TunnelPermissionException(this.message);
  @override
  String toString() => 'TunnelPermissionException: $message';
}

/// Raised for other tunnel setup/teardown failures.
class TunnelException implements Exception {
  final String message;
  TunnelException(this.message);
  @override
  String toString() => 'TunnelException: $message';
}

/// Platform-agnostic tunnel device + routing abstraction.
///
/// The SSTP data plane wires to this as: OS packets from [inbound] are sent to
/// the server, and packets received from the server are handed to
/// [writePacket] to inject into the OS.
///
/// A concrete backend ([LinuxTunBackend], and later a Windows/Wintun backend)
/// implements [open] to create the interface + install routing, and [close] to
/// revert everything it changed.
abstract class TunnelBackend {
  /// The actual interface name in use (valid after [open]).
  String get interfaceName;

  /// Creates the tunnel interface, assigns [TunnelConfig.assignedIp], brings it
  /// up, and installs routing. Throws [TunnelPermissionException] when it lacks
  /// CAP_NET_ADMIN, or [TunnelException] on other failures.
  Future<void> open(TunnelConfig config);

  /// IP packets read from the OS (to be forwarded to the VPN server). A
  /// broadcast stream chosen over a `readPacket()` future so it integrates
  /// directly with the async data-plane wiring.
  Stream<Uint8List> get inbound;

  /// Injects an IP packet received from the server into the OS.
  Future<void> writePacket(Uint8List packet);

  /// Tears down routing (reverting to the pre-open state) and closes the
  /// interface. Safe to call more than once and safe on partial setup.
  Future<void> close();
}

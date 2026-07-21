/// Pure-Dart SSTP + PPP VPN client (Milestone 1: handshake through IPCP).
library;

export 'src/logging.dart';
export 'src/sstp_session.dart' show SstpSession, HandshakeResult;
export 'src/tls_transport.dart' show TlsTransport;
export 'src/sstp_framer.dart' show SstpFramer;
export 'src/tunnel_backend.dart'
    show
        TunnelBackend,
        TunnelConfig,
        RouteMode,
        TunnelException,
        TunnelPermissionException;
export 'src/linux_tun.dart' show LinuxTunBackend;
export 'src/windows_tun.dart'
    show WindowsTunBackend, parseWindowsDefaultRoute, WindowsDefaultRoute;
export 'src/macos_utun.dart'
    show MacosUtunBackend, parseMacosDefaultRoute, MacosDefaultRoute;

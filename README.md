# sstp_client (Milestones 1–3)

Pure-Dart SSTP + PPP client. **Milestone 1** completes a full handshake against
a real SoftEther / VPN Gate server and obtains a tunnel IP via IPCP.
**Milestone 2** brings up a Linux TUN device and routes real traffic through the
tunnel, behind a platform-agnostic `TunnelBackend` interface. **Milestone 3**
adds a Windows backend over that same interface using Wintun — a new
implementation, not a rewrite.

## Layers

```
TlsTransport   dart:io SecureSocket + SSTP_DUPLEX_POST HTTP bootstrap
     |         (host and port both configurable; nothing assumes 443)
SstpFramer     reassembly buffer + SSTP control/data framing + echo replies
     |         (control frames vs. raw IP datagrams split to separate streams)
SstpSession    orchestrates the handshake, routes PPP frames per stage,
   / | \       exposes the data plane (inboundPackets / sendPacket)
 LCP  MSCHAPv2  IPCP        (PPP negotiation + auth + crypto binding)

TunnelBackend  abstract interface (open / inbound / writePacket / close)
   / | \
LinuxTunBackend        /dev/net/tun via dart:ffi ioctl(TUNSETIFF) + `ip` routing
WindowsTunBackend      Wintun adapter via dart:ffi (wintun.dll) + `netsh`/`route`
MacosUtunBackend       utun via PF_SYSTEM kernel-control socket + `ifconfig`/`route`
     |                 each with a dedicated reader isolate for blocking-free reads
```

Each layer is independently unit-testable. Packet encode/decode, the framer's
reassembly, the MSCHAPv2 crypto (RFC 2759 vectors), the data-plane framing, and
the TUN reader isolate (validated against a pipe) are all covered by offline
tests — no live server or root required.

## Run the handshake

```sh
dart pub get
dart run bin/main.dart --host <server> --port <port> \
    --username <user> --password <pass> [--verbose] [--verify-cert]
```

VPN Gate's public servers work as a live target (username `vpn`, password
`vpn`), e.g.:

```sh
dart run bin/main.dart --host 219.100.37.30 --port 443 \
    --username vpn --password vpn --verbose
```

`--verify-cert` is off by default because VPN Gate servers are typically
self-signed; the client logs a warning line for every unverified certificate.

## Tunnel real traffic (Milestone 2, Linux)

Creating a TUN device and changing routes needs `CAP_NET_ADMIN`, so run under
`sudo`. An AOT build avoids `sudo`/PATH/pub-cache friction:

```sh
dart compile exe bin/main.dart -o sstp

# Full-tunnel (default): all traffic egresses via the VPN. --test runs a
# before/after egress-IP check (via 1.1.1.1, no DNS needed) to prove flow.
sudo ./sstp --host 219.100.37.30 --port 443 \
    --username vpn --password vpn --tunnel --test --duration 30

# Split-tunnel: only the given prefixes go through the tunnel.
sudo ./sstp --host <server> --port 443 --username vpn --password vpn \
    --tunnel --route-mode split --route 10.0.0.0/8 --route 172.16.0.0/12
```

Without `--duration`, the tunnel stays up until Ctrl+C. Teardown (on Ctrl+C,
SIGTERM, `--duration` expiry, or any error) reverts every route it added,
brings the interface down, and closes the fd — which removes the
non-persistent TUN device. Reconnecting afterwards is clean; no leftover state.

Routing model:
- A host route pins the VPN server's real IP to the original gateway so the
  encrypted SSTP transport keeps flowing over the physical link.
- Full-tunnel overrides the default with `0.0.0.0/1` + `128.0.0.0/1` via the
  tunnel (it never deletes your `0.0.0.0/0`, so revert is just removing what it
  added).
- Host DNS is left untouched; the IPCP-assigned DNS is logged only.

If run without privilege, it fails with an explicit "needs
root/CAP_NET_ADMIN" error rather than silently.

## Tunnel real traffic (Milestone 3, Windows)

Windows has no built-in userspace TUN, so this backend uses **Wintun** (the
signed driver from [wintun.net](https://www.wintun.net)). Download the official
zip and place `wintun.dll` for the matching architecture (e.g. `bin/amd64/`)
next to the executable. Creating the adapter and changing routes needs an
**elevated (Administrator)** process.

```powershell
dart compile exe bin/main.dart -o sstp.exe
# copy wintun.dll beside sstp.exe

# From an elevated PowerShell / cmd:
.\sstp.exe --host 219.100.37.30 --port 443 `
    --username vpn --password vpn --tunnel --test --duration 30
```

The routing model is identical to Linux (server host-route pin + `0.0.0.0/1` /
`128.0.0.0/1` on-link overrides for full-tunnel; `--route` CIDRs for split),
applied with `netsh`/`route` and reverted in reverse order on teardown. Closing
the Wintun adapter drops any remaining bound routes. If not elevated, it fails
with an explicit "needs Administrator" error; if `wintun.dll` is missing, it
says so.

## Tunnel real traffic (macOS) — device layer verified, full path not

Status, precisely: the **device layer is verified on real macOS** (Apple Silicon,
in CI) — the kernel creates the utun interface, and a packet round-trips through
it in both directions. What has *not* been run is the full path against a live
VPN server (handshake → full-tunnel routing → egress swap), because no Mac was
available for an end-to-end run. The pieces that path adds are shared with Linux
and Windows, both of which are verified end-to-end, but treat the macOS
full-tunnel path as unproven until someone runs it.

macOS has utun built into the kernel (no third-party driver). The backend opens
a `PF_SYSTEM` / `SYSPROTO_CONTROL` socket, resolves `com.apple.net.utun_control`
with `ioctl(CTLIOCGINFO)`, and `connect()`s a `sockaddr_ctl` — which creates the
interface. Needs root.

```sh
dart compile exe bin/main.dart -o sstp
sudo ./sstp --host 219.100.37.30 --port 443 \
    --username vpn --password vpn --tunnel --test --duration 30 --verbose
```

The kernel picks the interface name (`utun0`, `utun1`, …); `--iface` is honoured
only if given as an explicit `utunN`. Routing is the same model as the other two
(`route add -host <server> <gw>` + `0.0.0.0/1` / `128.0.0.0/1` via the tunnel).

The one structural difference from Linux: **utun prefixes every packet with a
4-byte address family** in network byte order, where Linux's `IFF_NO_PI` TUN
carries raw IP. The backend strips it inbound and prepends it outbound. Note
`AF_INET6` is **30** on Darwin (10 on Linux) — that difference is unit-tested.

Constants verified against XNU (`bsd/sys/kern_control.h`, `bsd/net/if_utun.h`,
`bsd/sys/sys_domain.h`, `bsd/sys/socket.h`), not guessed:

| | |
|---|---|
| `struct ctl_info` | 100 B — `ctl_id` u32 @0, `ctl_name[96]` @4 |
| `struct sockaddr_ctl` | 32 B — `sc_len`@0 `sc_family`@1 `ss_sysaddr`@2 `sc_id`@4 `sc_unit`@8 |
| `CTLIOCGINFO` | `_IOWR('N',3,100)` = `0xC0644E03` |
| `PF_SYSTEM` / `SYSPROTO_CONTROL` / `AF_SYS_CONTROL` | 32 / 2 / 2 |

## Tests

```sh
dart test          # offline unit tests; no server, no root
```

CI (`.github/workflows/ci.yml`) additionally runs a **real TUN device
round-trip** on Linux and macOS runners, which is the only thing that exercises
the FFI layer — a unit test can only prove it compiles. It routes a dummy prefix
into the interface, pings it, answers the kernel's ICMP echo request through the
backend, and requires `ping` to succeed:

```sh
dart compile exe tool/tun_loopback_check.dart -o tun_check
sudo ./tun_check
```

This is what caught the `ioctl` variadic-ABI bug on Apple Silicon (see
`lib/src/libc.dart`): `ioctl(int, unsigned long, ...)` passes its third argument
on the *stack* on arm64, not in a register as on x86-64, so it must be declared
with `VarArgs`. A fixed declaration works on Linux x86-64 and silently hands the
kernel a garbage pointer on macOS.

## Scope / limitations

- Only CHAP/MSCHAPv2 auth is implemented. If a server insists on PAP or
  EAP-MSCHAPv2 the client fails loudly with the proposed protocol logged.
- IPv4 only. Inbound IPv6CP is answered with an LCP Protocol-Reject.
- Tunneling works on Linux (`/dev/net/tun`) and Windows (Wintun), both verified
  end-to-end against live servers. macOS (utun) has its device layer verified in
  CI, but its full-tunnel path has not been run against a live server yet.

See `ATTRIBUTION.md` for the MIT-licensed reference implementation this protocol
logic was derived from.

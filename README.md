# SplitWire

SplitWire is a VPN client and proxy for Windows with per-app split
tunneling. It runs tunnels from standard
[WireGuard](https://www.wireguard.com/) `.conf` files, and needs no
WireGuard app.

Each tunnel runs one of three ways:

- **Split VPN**: for the apps you pick, through a WireGuardNT network
  adapter. One tunnel is the Split VPN at a time, in one of two modes:
  - **include**: only the listed apps use the tunnel.
  - **exclude**: every app except the listed ones uses the tunnel.
- **VPN**: for every app, for the addresses in its `AllowedIPs`, as the
  WireGuard app does. Any number run at once, such as WARP for everything
  and an office VPN for `10.0.0.0/8`; the most specific range wins.
- **Proxy**: a local SOCKS5 and HTTP proxy, entirely in user space, for the
  apps you point at it. Any number run at once.

Traffic none of them takes goes out directly. Each tunnel connects straight
to its own server, never through another tunnel.

## Install

Download `splitwire-amd64.exe`, or `splitwire-arm64.exe` for an ARM PC,
from [Releases](https://github.com/nakomaru/splitwire/releases) and
double-click it. Setup asks for administrator rights once, then SplitWire
lives in the notification area and updates itself.

## Tunnels

Tunnels are files in `%APPDATA%\splitwire`. **Add** in the window imports
them from the WireGuard app or a file, creates a free Cloudflare WARP
tunnel, or starts an empty one. Split tunneling settings go in a
`[SplitWire]` section, which the window edits; see
[example.conf](example.conf):

| Key | Values | Default |
|---|---|---|
| `Mode` | `include` or `exclude`, for the Split VPN | `full`: not a Split VPN |
| `App` | path to an app; `%VAR%` and `*` globs allowed; repeatable | |
| `KillSwitch` | `auto`, `on`, `off` | `auto`: on with a default route |
| `AllowLAN` | `on`, `off`: exempt the LAN from the kill switch | `off` |
| `StrictDNS` | `on`, `off`: block DNS servers other than the tunnel's | `on` |
| `Proxy` | port, or address and port | picked from 1080 up |

## Proxies

Point an app's SOCKS5 or HTTP proxy setting at `127.0.0.1` and the tunnel's
port; for Chrome and Edge, launch them with
`--proxy-server=socks5://127.0.0.1:1080`. In Firefox, also turn on "Proxy
DNS when using SOCKS v5".

## Always direct

Destinations on the Always direct list never go through a VPN, whatever
ranges the VPNs carry: for example, an office VPN server that another VPN
client reaches from a virtual machine. List address ranges, addresses or
host names; names are looked up when a tunnel connects. An include mode
Split VPN's apps still reach them through the Split VPN.

```
splitwire direct add 203.0.113.0/24 vpn.office.example
```

## Command line

```
splitwire import           # copy tunnels from the WireGuard app
splitwire up home          # run a tunnel until Ctrl+C
splitwire proxy warp       # run a tunnel as a proxy until Ctrl+C
splitwire help             # every command
```

The installed copy is `%ProgramFiles%\splitwire\bin\splitwire.exe`.

## Updates

SplitWire updates itself, and installs only updates signed by its author.

## Limits

- Include mode cuts listed apps off from the local network.
- Two VPNs cannot carry the same range.
- A tunnel's `DNS` servers resolve names for every app, including the ones
  split tunneling leaves out.
- One kill switch and DNS restriction apply at a time: those of the tunnel
  that turned them on first, until it stops.
- Apps keep existing connections' routes, so start the tunnel first.
- Proxies work only for apps with proxy settings, and take no password.
- The Split VPN cannot run while the Mullvad VPN app runs: the split tunnel
  driver takes one controller at a time.

## Uninstalling

**Uninstall SplitWire...** in the menu, or `splitwire cleanup`, removes
everything except your tunnel files, unless you choose to delete them too.

## Building and releasing

`.\build.ps1` builds `splitwire.exe`. To release, raise the version in
`main.go` and `winres\winres.json`, run `go generate`, commit and push,
then run `.\release.ps1 -Publish`, which builds, signs with
`keys\release.key` (gitignored; keep a backup) and creates the GitHub
release.

## Licenses and trademarks

SplitWire is under the [MIT license](LICENSE). `internal/firewall` and `internal/netcfg/mtu.go` are adapted from
[wireguard-windows](https://git.zx2c4.com/wireguard-windows/) (MIT). The
split tunnel driver is Mullvad's
[win-split-tunnel](https://github.com/mullvad/win-split-tunnel), which
SplitWire downloads at run time and does not redistribute.

SplitWire is an independent project, not made, endorsed or sponsored by the
WireGuard project, Jason A. Donenfeld, Mullvad or Cloudflare. "WireGuard"
and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld.

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
  and an office VPN for `10.0.0.0/8`; the most specific range wins. A VPN
  without a default route whose `DNS` line also names domains, such as
  `DNS = 10.0.0.53, corp.example`, answers only for those domains, through
  the VPN; every other name goes to the usual DNS servers.
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
them from the WireGuard app, a file, or a QR code in an image file, on the
clipboard or on the screen; creates a free Cloudflare WARP tunnel; or
starts an empty one. Split tunneling settings go in a
`[SplitWire]` section, which the window edits; see
[example.conf](example.conf):

| Key | Values | Default |
|---|---|---|
| `Mode` | `include` or `exclude`, for the Split VPN | `full`: not a Split VPN |
| `App` | path to an app; `%VAR%` and `*` globs allowed; repeatable | |
| `Proxy` | port, or address and port | picked from 1080 up |

The **Details** tab edits a tunnel's WireGuard settings, those of its
interface or of one peer at a time: keys, addresses, DNS servers, listen
port, MTU, endpoint, keepalive and allowed IPs, and adds and removes peers.
It checks each field as you type, and Save writes only the fields that
changed, keeping the file's comments. **Exclude private IPs** takes the
local network's private ranges out of a peer that carries every address.
**Test**, beside MTU, pings the peer's endpoint over IPv4 or IPv6 with
packets that may not be split, finds the largest that arrives, and fills in
the MTU that fits it. SplitWire never runs `PreUp`, `PostUp`, `PreDown` or
`PostDown` scripts, and says so when a tunnel has them.

## Overview

The window's Overview, at the top of the tunnel list, shows where traffic
goes, as Windows routes it, including ranges that lie inside another
tunnel's and which one wins. It holds the settings for every tunnel:

- **Kill switch**: while a VPN carries every address, blocks traffic outside
  the tunnels, so nothing leaks if it drops. On at first.
- **Allow the local network**: lets the kill switch pass the LAN.
- **Use only the tunnels' DNS servers**: while a tunnel sets DNS servers,
  blocks every other DNS server. On at first.
- **Always direct**: see below.

## Proxies

Point an app's SOCKS5 or HTTP proxy setting at `127.0.0.1` and the tunnel's
port; for Chrome and Edge, launch them with
`--proxy-server=socks5://127.0.0.1:1080`. In Firefox, also turn on "Proxy
DNS when using SOCKS v5".

## Always direct

Destinations on the Always direct list, in the Overview, never go through a
VPN, whatever ranges the VPNs carry: for example, an office VPN server that
another VPN client reaches from a virtual machine. List address ranges,
addresses or host names; names are looked up when a tunnel connects. An
include mode Split VPN's apps still reach them through the Split VPN. From
a shell:

```
splitwire direct add 203.0.113.0/24 vpn.office.example
```

## Command line

```
splitwire import                 # copy tunnels from the WireGuard app
splitwire qr code.png            # import a tunnel from a QR code; also --clipboard or --screen
splitwire connect home           # connect a tunnel in the service, as the app does
splitwire connect warp --proxy   # ... as a proxy
splitwire disconnect warp        # disconnect it
splitwire status                 # tunnels, peers and the split tunnel driver
splitwire settings               # the Overview's settings
splitwire settings allowlan on   # change one
splitwire proxy warp             # run a tunnel as a proxy until Ctrl+C
splitwire help                   # every command
```

`connect`, `disconnect`, `direct`, `settings` and `status` go through the
SplitWire service and need no administrator rights, so scripts and agents
can use them. Commands that change the system ask for administrator rights; from a
console without a window, such as a script runner's, where no one sees the
prompt, they fail at once and say so.

The installed copy is `%ProgramFiles%\splitwire\bin\splitwire.exe`.

## Updates

SplitWire updates itself, and installs only updates signed by its author.
Running tunnels disconnect briefly during an update and reconnect.

## Limits

- Include mode cuts listed apps off from the local network.
- Two VPNs cannot carry the same range.
- A tunnel's `DNS` servers resolve names for every app, including the ones
  split tunneling leaves out.
- Apps keep existing connections' routes, so start the tunnel first.
- Proxies work only for apps with proxy settings, and take no password.
- The Split VPN cannot run while the Mullvad VPN app runs: the split tunnel
  driver takes one controller at a time.

## Uninstalling

**Uninstall SplitWire...** in the menu, or `splitwire cleanup`, removes
everything except your tunnel files and the Overview's settings, which a
later install picks up again. Either can go too: in the menu, or with
`--configs` and `--settings`.

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

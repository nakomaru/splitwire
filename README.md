# splitwire

WireGuard for Windows with per-app split tunneling. One executable; it
downloads and installs everything else it needs on first use.

- **full**: routes by `AllowedIPs`, the same as the WireGuard app.
- **include**: only the listed apps (and their child processes) use the tunnel.
- **exclude**: everything except the listed apps uses the tunnel.

## Quick start

```
go build -o splitwire.exe .
splitwire check home.conf     # validate and show routes, DNS and apps
splitwire up home.conf        # run until Ctrl+C
splitwire install home.conf   # or run as a service that starts at boot
```

A configuration is an ordinary WireGuard `.conf` plus an optional `[Splitwire]`
section; see [example.conf](example.conf). The tunnel takes its name from
the file name. `splitwire apps firefox` lists running programs whose paths
contain "firefox", for filling in `App` lines.

Commands that change the system ask for administrator rights through UAC
and continue in a new console window.

## Commands

| Command | Effect |
|---|---|
| `up <conf>` | Run a tunnel in the console until Ctrl+C |
| `check <conf>` | Parse a configuration and print its routes, DNS, kill switch and apps |
| `apps [filter]` | List running programs with their full paths |
| `install <conf>` | Copy the configuration and executable into `%ProgramFiles%\splitwire` and register an auto-start service `splitwire$<name>` |
| `uninstall <name>` | Stop and delete that service and its stored configuration |
| `start <name>`, `stop <name>` | Control an installed tunnel |
| `status [name]` | Installed tunnels, peer handshakes and transfer, driver state |
| `bootstrap` | Install the components without bringing a tunnel up |
| `cleanup` | Remove the driver service, firewall objects and `%ProgramFiles%\splitwire` |

`install` expands `%VARIABLES%` and globs in `App` lines as the installing
user, because the service runs as SYSTEM with a different profile.

## `[Splitwire]` keys

| Key | Values | Default |
|---|---|---|
| `Mode` | `full`, `include`, `exclude` | `full` |
| `App` | absolute path; `%VAR%` and `*` `?` `[...]` globs allowed; repeatable | |
| `KillSwitch` | `auto`, `on`, `off` (full and exclude modes) | `auto`: on when `AllowedIPs` has a default route |
| `AllowLAN` | `on`, `off`: exempt private networks from the kill switch | `off` |
| `StrictDNS` | `on`, `off`: block DNS servers other than `[Interface] DNS` | `on` |

## What it installs

Everything lives in `%ProgramFiles%\splitwire`:

- `bin\wireguard.dll`: WireGuardNT 1.1 from download.wireguard.com, pinned by
  SHA-256. It installs the WireGuardNT kernel driver on first use; the
  WireGuard app uses the same driver.
- `bin\mullvad-split-tunnel.sys`: Mullvad's signed split tunnel driver
  (version 1.3.0.0), pinned by SHA-256. It is read straight out of the
  Mullvad VPN 2026.5 installer on cdn.mullvad.net with HTTP range requests,
  which downloads about 256 KiB of the 134 MB file. It runs as the
  demand-start kernel service `mullvad-split-tunnel`.
- `bin\splitwire.exe`, `configs\`, `logs\`: for installed services. `configs`
  and `logs` are readable only by SYSTEM and Administrators.

## How it works

The Mullvad driver rebinds sockets of chosen processes from one local
address (its "tunnel" address) to another (its "internet" address), and
blocks those processes on the first address. splitwire uses it as designed for
exclude mode, and swaps the two addresses for include mode:

| Mode | Driver "tunnel" address | Driver "internet" address | Tunnel default route |
|---|---|---|---|
| include | physical interface | WireGuard interface | metric 9000, used only by rebound sockets |
| exclude | WireGuard interface | physical interface | metric 0 |

Windows sends from a bound address only over routes on that address's
interface, so rebound sockets leave through the other interface. The
physical address is tracked as networks change. Child processes inherit the
setting from their parent.

The kill switch and DNS restriction are WFP filters adapted from
wireguard-windows. They live in two sublayers whose keys are handed to the
driver, so the driver's own permits for listed apps outrank them.

## Limits

- **Include mode cuts listed apps off from the local network.** The driver
  rebinds their LAN connections into the tunnel too. Ranges in `AllowedIPs`
  (such as a home LAN) stay reachable through the tunnel.
- **DNS is system-wide.** Apps resolve names through the Windows DNS client
  service, which no `App` line covers. With `DNS` set, every app's lookups
  go to those servers through the tunnel, and other DNS servers are blocked
  unless `StrictDNS = off`. If the tunnel goes down, name resolution for the
  whole system stops with it. Without `DNS`, listed apps resolve names with
  the system's normal DNS servers. Apps with built-in DNS over HTTPS resolve
  through the tunnel either way.
- **Existing connections keep their route** until the app reconnects; start
  the tunnel before the apps it covers.
- One splitwire tunnel runs at a time. The driver admits one controller, so the
  Mullvad VPN app cannot run alongside splitwire.
- If splitwire is killed without shutting down, the driver stays engaged until
  the next `up` or `cleanup` resets it. In include mode the listed apps have
  no network until then; the WireGuard adapter itself disappears with the
  process.

## Licenses

`internal/firewall` and `internal/netcfg/mtu.go` are adapted from
[wireguard-windows](https://git.zx2c4.com/wireguard-windows/) (MIT, see
`internal/firewall/LICENSE`). The split tunnel driver is
[mullvad/win-split-tunnel](https://github.com/mullvad/win-split-tunnel)
(GPL-3.0 or MPL-2.0); splitwire downloads Mullvad's signed build at run time
and does not redistribute it.

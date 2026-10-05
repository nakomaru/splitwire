# SplitWire

WireGuard for Windows with per-app split tunneling, in one executable:
double-clicked, `splitwire.exe` is a notification area app; run from a
shell, it is a command line. It downloads and installs everything else it
needs on first use, so the WireGuard app is not required.

Any tunnel runs one of two ways:

- **VPN**: through a network adapter, for every app, in one of three modes.
  One tunnel runs as the VPN at a time.
  - **full**: routes by `AllowedIPs`, the same as the WireGuard app.
  - **include**: only the listed apps (and their child processes) use the tunnel.
  - **exclude**: everything except the listed apps uses the tunnel.
- **Proxy**: entirely in user space, as a local SOCKS5 and HTTP proxy that
  apps with proxy settings point at. Any number of tunnels run as proxies
  at once, beside the VPN, so different apps can use different tunnels.

## Quick start

Double-click `splitwire.exe`. It offers to set itself up, which asks for
administrator rights once, then opens its window and sits in the
notification area. In the window, **Add** imports existing tunnels from the
WireGuard app or a file, creates a WARP tunnel, or starts an empty one.

From a shell:

```
.\build.ps1                # builds splitwire.exe
splitwire import           # copy tunnels from the WireGuard app
splitwire check home       # validate and show routes, DNS and apps
splitwire up home          # run until Ctrl+C
splitwire proxy warp       # or run it as a proxy until Ctrl+C (no admin needed)
splitwire install home     # or run as a service that starts with Windows
```

Configurations live in `%APPDATA%\splitwire\<name>.conf`; commands take the
name, or a path to a `.conf` anywhere else. A configuration is an ordinary
WireGuard `.conf` plus an optional `[SplitWire]` section; see
[example.conf](example.conf). `splitwire apps firefox` lists running
programs whose paths contain "firefox", for filling in `App` lines.

`import` copies tunnels out of the WireGuard app. The app keeps them
encrypted for the SYSTEM account, so SplitWire decrypts them through a
temporary service that runs as SYSTEM and deletes itself afterward. Each
imported file ends with a commented `[SplitWire]` section. `up <name>`
imports that tunnel by itself when its file does not exist yet.

Commands that change the system ask for administrator rights through UAC
and continue in a new console window.

## The window

Starting SplitWire, from the Start menu or by double-clicking it, opens its
window; so does clicking the notification area icon. Starting it again
while it runs brings the window back. At sign-in it starts in the
background.

The window lists the tunnels on the left, each with a dot for its state:
green while it runs as the VPN, blue as a proxy, amber while it connects,
red after a failure or for a file with a problem. **Add** creates or
imports tunnels and opens the configuration folder; **Delete** moves a
tunnel's file to the Recycle Bin. Right-clicking a tunnel connects,
disconnects, renames (F2) or deletes (Del) it.

For the selected tunnel:

- **Off, VPN and Proxy** run it one way or stop it. The line under its name
  shows the connection, and while it runs a graph shows the received and
  sent rates of the last three minutes with the totals. A tunnel edited
  since it connected offers **Reconnect**.
- **VPN** holds the settings for running as the VPN. **Split tunneling**
  is Off (every app, routed by `AllowedIPs`), Include (only the listed
  apps) or Exclude (every app but the listed ones). **Add apps** offers the
  programs running now, the ones Explorer recorded as recently started
  (when Windows tracks app launches) and the Start menu's, with a search
  box that also takes a typed path or pattern, and **Browse...**. Folders
  named for a version become `*`, so `...\Discord\app-1.0.9163\Discord.exe`
  is added as `...\Discord\app-*\Discord.exe` and keeps working after
  updates. Each entry shows its icon and name, and warns when it matches no
  file. With split tunneling off, the list stays in the file for Include
  and Exclude. Below the list are the kill switch with its local network
  exception, shown for Off and Exclude, and strict DNS, shown when the
  tunnel sets `DNS`; their tooltips say what they do.
- **Proxy** holds the settings for running as a proxy: the port (refusing
  ports another tunnel or program holds), a button to copy the address,
  and **Chain through the VPN** (`ProxyVia = vpn`).
- **Details** shows the public key, with a button to copy it, the
  addresses, the DNS servers, and the first peer's endpoint and allowed IPs.
- **Text** edits the whole file with its sections, keys, values and
  comments in colors, checking it on every keystroke and underlining the
  line of a problem; **Save** (Ctrl+S) is ready once it checks out.

The window writes each change straight to the file, keeping its comments,
so the file stays the one source of truth and other editors can open it
too. Changes reach a running tunnel when it reconnects.

## Notification area app

The icon is gray when no tunnel runs, amber while one connects or
disconnects, green when tunnels are up and red after a failure. Clicking it
opens the window; right-clicking shows the menu:

```
Office VPN, WARP proxy 127.0.0.1:1080
  Office (VPN): handshake 4s ago, received 1.20 GiB, sent 31.00 MiB
  WARP (proxy 127.0.0.1:1080): handshake 9s ago, ...
  Apply changes to WARP
Open SplitWire
VPN: Office   >  Off / Office - include, 2 apps / WARP - ... (proxy now)
Proxies         >  WARP - 127.0.0.1:1080 / backup - port picked from 1080 on first use
Disconnect all
Reconnect tunnels when Windows starts
Start SplitWire at sign-in
Show manager log, Uninstall SplitWire..., Quit
```

- **VPN** picks the one tunnel that routes apps by its `Mode`, or Off.
- **Proxies** ticks any number of tunnels to serve as local proxies. A
  tunnel runs one way at a time, so picking it in one list moves it out of
  the other.
- The top lines show each running tunnel's last handshake and transfer,
  failures, and an **Apply changes** entry when a running tunnel's file was
  edited.
- **Reconnect tunnels at boot** brings whatever runs back up when Windows
  starts, before anyone signs in, through the manager service.
- **Start SplitWire at sign-in** opens the app when you sign in, through
  your user's Run entry; the notification area exists only once you sign in.
- **Uninstall SplitWire...** removes everything, as `splitwire cleanup`
  below, and asks whether to delete your tunnel configurations too.

The first run opens the install window: checkboxes with descriptions, grouped
under Install and Startup, and an Install button that asks for administrator
rights once. Every install also puts in place the WireGuard driver
(WireGuardNT from the WireGuard project; wireguard.dll installs it with its
first adapter, so setup creates a temporary one) and Mullvad's open source
split tunnel driver, and the window says so.

- **Add SplitWire to the Start menu**: your own Start menu; each user who
  runs setup gets their own.
- **Start SplitWire at sign-in**.
- **Reconnect tunnels when Windows starts**: the menu changes it later too.
- **Import tunnels from the WireGuard app**, when that app is installed (on
  while `%APPDATA%\splitwire` holds no tunnels).
- **Delete this file afterward**, when run from outside Program Files: the
  installed copy deletes the file once the setup process has exited, and
  only when it is identical to the installed executable.

Setup copies the executable to `%ProgramFiles%\splitwire\bin`, installs the
manager service and switches to the installed copy. Double-clicking a
different `splitwire.exe` later opens the same window as an update, with
both versions in its text and each choice set to its current state, so an
update can change them too; an identical copy opens the installed app.
Installing cancels deletions that an earlier uninstall left for the next
restart, so a reinstall before restarting stays.

The window, the dialogs and the notification area menu follow the Windows
light or dark mode, in the colors of Windows 11, with the primary buttons
and selections in the system accent color. High contrast themes keep the
system colors.

The manager service runs as SYSTEM and does the privileged work; the app
runs as you and talks to it over the pipe `\\.\pipe\splitwire`, which only
SplitWire's users, SYSTEM and Administrators can open. The app reads your configurations
and expands `%VARIABLES%` in `App` lines as you, so switching tunnels never
prompts.

The executable's manifest asks Windows 11 24H2 and later to start it
without a console window unless a shell's console is there to share, so
double-clicking shows no console. On earlier Windows a console window can
flash as it starts.

## Several users

Each Windows account that runs setup becomes one of SplitWire's users,
listed by SID in `%ProgramFiles%\splitwire\configs\users`, which only SYSTEM
and Administrators can read. Setup passes the app's own account, so a
standard user who types an administrator's password is the one added. Every
user keeps their own tunnel files, Start menu shortcut and sign-in setting;
the running tunnels are the PC's, so each user sees and can change them, and
one tunnel runs as the VPN for everyone.

While other users remain, the uninstall window offers to keep SplitWire for
them, which removes only your access (`splitwire manager leave`), your
shortcut and your sign-in entry, and optionally your configurations.

## Proxies

A tunnel running as a proxy listens on its `Proxy` address, `127.0.0.1` and
a port from 1080 up by default. The first time a tunnel runs as a proxy,
SplitWire picks a port no other tunnel claims and writes it to the file as
`Proxy = 1080`, so app settings keep working. The port serves both
protocols:

| App setting | Value |
|---|---|
| SOCKS5 (Firefox, qBittorrent, Telegram, curl `-x socks5h://`) | `127.0.0.1:1080` |
| HTTP or HTTPS proxy | `127.0.0.1:1080` |
| Chrome and Edge | launch with `--proxy-server=socks5://127.0.0.1:1080` |

Each proxy tunnel is a complete WireGuard client with its own TCP/IP stack
(wireguard-go and gVisor's netstack). Connections an app makes through the
proxy leave from the tunnel's `Address`; only the tunnel's encrypted UDP
packets touch the real network. Host names resolve through the tunnel's
`DNS` servers, or through the system's when it sets none; in Firefox, turn
on "Proxy DNS when using SOCKS v5" so names go through the proxy. When a
site has both IPv6 and IPv4 addresses, the proxy starts on IPv6 and adds
IPv4 after 250 ms, keeping whichever connects first, so a tunnel with
broken IPv6 still connects quickly.

A proxy tunnel's own packets follow the system routes, so a VPN tunnel in
full or exclude mode with a default route carries them: `WARP` as a proxy
inside `Office` as a full VPN leaves through the office and then Cloudflare. `ProxyVia = vpn`
makes that explicit for any VPN mode: the packets go only through the VPN
tunnel, and stop while no VPN runs.

## Commands

| Command | Effect |
|---|---|
| (none), `tray` | Start the app and open its window; `tray --background` starts it without the window, as at sign-in |
| `import [--force] [name...]` | Copy tunnels from the WireGuard app; existing files stay unless `--force` |
| `up <tunnel>` | Run a tunnel in the console until Ctrl+C |
| `warp [name]` | Register a free Cloudflare WARP device and save it as a tunnel, `WARP` by default |
| `proxy <tunnel>` | Run a tunnel as a proxy in the console until Ctrl+C, without administrator rights |
| `check <tunnel>` | Parse a configuration and print its routes, DNS, kill switch and apps |
| `apps [filter]` | List running programs with their full paths |
| `install <tunnel>` | Copy the configuration and executable into `%ProgramFiles%\splitwire` and register an auto-start service `splitwire$<name>` |
| `uninstall <name>` | Stop and delete that service and its stored configuration |
| `start <name>`, `stop <name>` | Control an installed tunnel |
| `status [name]` | Configured and installed tunnels, peer handshakes and transfer, driver state |
| `manager install [options]` | Install or update the manager service the app uses, adding the current user, or `--user=SID`, to its users. `--boot`/`--no-boot` sets reconnecting when Windows starts, `--wireguard-driver` and `--split-tunnel-driver` install those drivers now, `--import` imports from the WireGuard app (`manager leave [--user=SID]` removes a user again, `manager uninstall` removes the service) |
| `bootstrap` | Install wireguard.dll, the WireGuardNT driver and the split tunnel driver without bringing a tunnel up |
| `cleanup [--configs] [--keep-wireguardnt]` | Uninstall everything (see below); `--configs` also deletes `%APPDATA%\splitwire`, `--keep-wireguardnt` keeps the WireGuardNT driver |

`install` expands `%VARIABLES%` and globs in `App` lines as the installing
user, because the service runs as SYSTEM with a different profile.

## `[SplitWire]` keys

| Key | Values | Default |
|---|---|---|
| `Mode` | `full`, `include`, `exclude` | `full` |
| `App` | absolute path; `%VAR%` and `*` `?` `[...]` globs allowed; repeatable | |
| `KillSwitch` | `auto`, `on`, `off` (full and exclude modes) | `auto`: on when `AllowedIPs` has a default route |
| `AllowLAN` | `on`, `off`: exempt private networks from the kill switch | `off` |
| `StrictDNS` | `on`, `off`: block DNS servers other than `[Interface] DNS` | `on` |
| `Proxy` | port, or address and port, such as `0.0.0.0:1080` to serve the LAN | picked from 1080 up on first use |
| `ProxyVia` | `auto`: proxy packets follow the system routes; `vpn`: only through the VPN tunnel | `auto` |

`Mode`, `App`, `KillSwitch`, `AllowLAN` and `StrictDNS` apply when the tunnel
runs as a VPN; `Proxy` and `ProxyVia` when it runs as a proxy.

## What it installs

Everything lives in `%ProgramFiles%\splitwire`:

- `bin\wireguard.dll`: WireGuardNT 1.1 from download.wireguard.com, pinned by
  SHA-256. It installs the WireGuardNT kernel driver on first use; the
  WireGuard app uses the same driver.
- `bin\mullvad-split-tunnel.sys`: Mullvad's signed split tunnel driver
  (version 1.3.0.0), pinned by SHA-256. It is read straight out of the
  Mullvad VPN 2026.5 installer on cdn.mullvad.net with HTTP range requests,
  which downloads about 256 KiB of the 134 MB file. It runs as the
  demand-start kernel service `mullvad-split-tunnel`. When the Mullvad VPN
  app has installed that service, SplitWire uses it as the app left it,
  while the Mullvad daemon is stopped, and never changes or removes it.
- `bin\splitwire.exe`, `configs\`, `logs\`: the installed app, which the
  services run, and the services' configuration copies and logs. `configs`
  and `logs` are readable only by SYSTEM and Administrators.

## WARP tunnels

**Add > Create a WARP tunnel...** in the window, or `splitwire warp`, registers a free
device with Cloudflare WARP and saves it as a tunnel named `WARP` (or
`WARP-2` and so on). It speaks the registration API of Cloudflare's WARP
app, which Cloudflare does not document and could change; wgcf and similar
tools use the same requests. The file's first comments record the device ID
and its token, which removing the device from Cloudflare needs. A WARP
tunnel works as a VPN or as a proxy, and as a proxy inside a full VPN
tunnel it makes a double hop.

## Uninstalling

`splitwire cleanup`, or **Uninstall SplitWire...** in the menu, removes the
following. The menu's uninstall window has checkboxes for deleting the
configurations (off) and the WireGuardNT driver (on, and unavailable while
the WireGuard app is installed).

- the manager service, every `splitwire$<name>` tunnel service and a
  leftover `splitwire-wg-import` service
- the `mullvad-split-tunnel` driver service, after resetting the driver,
  when it runs SplitWire's copy; the Mullvad VPN app's stays
- the SplitWire firewall provider and sublayers
- the WireGuardNT driver, unless the WireGuard app is installed and uses it
  or `--keep-wireguardnt` is given
- `%ProgramFiles%\splitwire`; files still in use, such as the running app,
  are deleted at the next restart
- the Start menu shortcut, the sign-in entry and the app's files in `%TEMP%`
- with `--configs`, `%APPDATA%\splitwire`

Windows keeps a network profile entry for every network adapter it has
seen, including the tunnels' adapters, under
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList`; SplitWire
leaves those, as the WireGuard app does.

## Private keys

Configurations are plain WireGuard `.conf` files, so Notepad and other
WireGuard tools read them. `%APPDATA%\splitwire` is readable only by you,
SYSTEM and Administrators. The copies the services keep in
`%ProgramFiles%\splitwire\configs` are readable only by SYSTEM and
Administrators. The WireGuard app also encrypts its copies with DPAPI for
the SYSTEM account; that protects them from backups and copies of the
files, but anyone with administrator rights can still decrypt them.
Against a stolen or copied disk, the protection that works is BitLocker
(or another full disk encryption), which covers every file at once.

## How it works

The Mullvad driver rebinds sockets of chosen processes from one local
address (its "tunnel" address) to another (its "internet" address), and
blocks those processes on the first address. SplitWire uses it as designed for
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
- One tunnel runs as the VPN at a time. The driver admits one controller, so
  the Mullvad VPN app cannot run alongside SplitWire either.
- **Proxies work only for apps with proxy settings.** Most games and voice
  chat have none. UDP goes through a proxy only for apps that use SOCKS5 UDP
  (UDP ASSOCIATE); browsers use TCP through a proxy.
- **Any program on the PC can use a proxy port**, and with a `Proxy` address
  other than loopback, any device that reaches it. The proxies take no
  password.
- One tunnel cannot run as the VPN and a proxy at once: both would use the
  same WireGuard key, and the server tracks one endpoint per key.
- If SplitWire is killed without shutting down, the driver stays engaged until
  the next `up` or `cleanup` resets it. In include mode the listed apps have
  no network until then; the WireGuard adapter itself disappears with the
  process.

## Licenses

`internal/firewall` and `internal/netcfg/mtu.go` are adapted from
[wireguard-windows](https://git.zx2c4.com/wireguard-windows/) (MIT, see
`internal/firewall/LICENSE`). The split tunnel driver is
[mullvad/win-split-tunnel](https://github.com/mullvad/win-split-tunnel)
(GPL-3.0 or MPL-2.0); SplitWire downloads Mullvad's signed build at run time
and does not redistribute it.

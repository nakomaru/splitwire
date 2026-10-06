package config

// ExampleSection is a [SplitWire] section whose settings are all commented
// examples, appended to tunnels splitwire creates or imports. Without
// uncommented settings the tunnel runs with the defaults.
const ExampleSection = `[SplitWire]
# Settings for SplitWire; the WireGuard app ignores this section. Remove a
# leading # to use a line.

# As the Split VPN, Mode picks the apps that use the tunnel:
#   include  only the listed apps
#   exclude  every app except the listed ones
# Child processes follow their parent, so a launcher covers its games. As a
# VPN, the tunnel routes every app by AllowedIPs and ignores Mode and App.

# Only two apps use the tunnel:
# Mode = include
# App = C:\Program Files\Mozilla Firefox\firefox.exe
# App = %LOCALAPPDATA%\Discord\app-*\Discord.exe

# Every app except two uses the tunnel:
# Mode = exclude
# App = C:\Program Files (x86)\Steam\steam.exe
# App = C:\Program Files\qBittorrent\qbittorrent.exe

# App takes absolute paths, %VARIABLES% and * ? globs. "splitwire apps
# firefox" lists the paths of running programs that match.

# Block traffic outside the tunnel while it runs, except in include mode.
# auto means on when AllowedIPs has a default route.
# KillSwitch = auto
# Keep the local network reachable with the kill switch on.
# AllowLAN = off
# Block DNS servers other than [Interface] DNS.
# StrictDNS = on

# As a proxy: the SOCKS5 and HTTP port, picked on first use, or an address
# and port such as 0.0.0.0:1080 to serve the local network.
# Proxy = 1080
`

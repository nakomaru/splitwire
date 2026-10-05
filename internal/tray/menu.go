package tray

import (
	"fmt"
	"strings"

	"fyne.io/systray"

	"splitwire/internal/config"
	"splitwire/internal/ipc"
	"splitwire/internal/stats"
	"splitwire/internal/userconf"
)

// tunnelMenu is a tunnel's items across the menu.
type tunnelMenu struct {
	// In the top section, shown while the tunnel runs or failed.
	status, apply *systray.MenuItem
	// In the VPN and Proxies submenus.
	vpn, proxy *systray.MenuItem
}

func (a *app) onClick(item *systray.MenuItem, gen chan struct{}, f func()) {
	go func() {
		for {
			select {
			case <-item.ClickedCh:
				go f()
			case <-gen:
				return
			}
		}
	}()
}

// rebuild recreates the menu, which happens when the tunnel list changes.
func (a *app) rebuild() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.gen != nil {
		close(a.gen)
	}
	gen := make(chan struct{})
	a.gen = gen
	systray.ResetMenu()

	a.summaryMI = systray.AddMenuItem("SplitWire", "")
	a.summaryMI.Disable()
	a.menus = make(map[string]*tunnelMenu)
	for _, name := range a.names {
		name := name
		m := &tunnelMenu{
			status: systray.AddMenuItem("", ""),
			apply:  systray.AddMenuItem("Apply changes to "+name, "Reconnect with the edited configuration"),
		}
		m.status.Disable()
		a.onClick(m.apply, gen, func() { a.apply(name) })
		a.menus[name] = m
	}
	systray.AddSeparator()

	a.onClick(systray.AddMenuItem("Open SplitWire", "Tunnels, their apps and settings"), gen, a.openWindow)
	a.vpnMI = systray.AddMenuItem("VPN", "One tunnel routes apps by its Mode")
	a.vpnOffMI = a.vpnMI.AddSubMenuItemCheckbox("Off", "", true)
	a.onClick(a.vpnOffMI, gen, a.vpnOff)
	a.proxiesMI = systray.AddMenuItem("Proxies", "Any number of tunnels serve local SOCKS5 and HTTP proxies")
	if len(a.names) == 0 {
		a.vpnMI.AddSubMenuItem("No tunnels yet", "").Disable()
		a.proxiesMI.AddSubMenuItem("No tunnels yet", "").Disable()
	}
	for _, name := range a.names {
		name := name
		m := a.menus[name]
		m.vpn = a.vpnMI.AddSubMenuItemCheckbox(name, "", false)
		a.onClick(m.vpn, gen, func() { a.toggleVPN(name) })
		m.proxy = a.proxiesMI.AddSubMenuItemCheckbox(name, "", false)
		a.onClick(m.proxy, gen, func() { a.toggleProxy(name) })
	}
	systray.AddSeparator()

	a.downAllMI = systray.AddMenuItem("Disconnect all", "")
	a.onClick(a.downAllMI, gen, func() { a.stop("") })
	a.bootMI = systray.AddMenuItemCheckbox("Reconnect tunnels at boot", "Bring the running tunnels back up when Windows starts, before sign-in", false)
	a.onClick(a.bootMI, gen, a.toggleBoot)
	a.loginMI = systray.AddMenuItemCheckbox("Start SplitWire at sign-in", "", runAtLogin())
	a.onClick(a.loginMI, gen, a.toggleLogin)
	systray.AddSeparator()
	a.onClick(systray.AddMenuItem("Show manager log", ""), gen, a.showLog)
	a.setupMI = systray.AddMenuItem("Set up SplitWire (administrator)...", "Install SplitWire and its background service")
	a.setupMI.Hide()
	a.onClick(a.setupMI, gen, a.setup)
	a.uninstallMI = systray.AddMenuItem("Uninstall SplitWire...", "Remove everything SplitWire installed")
	a.onClick(a.uninstallMI, gen, a.uninstall)
	a.onClick(systray.AddMenuItem("Quit", "Close the app; running tunnels stay up"), gen, systray.Quit)

	a.refreshLocked()
}

func (a *app) refresh() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshLocked()
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// vpnDetail describes how a configuration routes as a VPN.
func vpnDetail(c *config.Config) string {
	if c.Mode == config.ModeFull {
		return "all traffic by AllowedIPs"
	}
	return c.Mode.String() + ", " + plural(len(c.Apps), "app")
}

// proxyDetail describes where a configuration's proxy listens.
func proxyDetail(c *config.Config) string {
	d := fmt.Sprintf("port picked from %d on first use", userconf.FirstProxyPort)
	if c.Proxy.IsValid() {
		d = c.Proxy.String()
	}
	if c.ProxyVia == config.ViaVPN {
		d += ", through the VPN"
	}
	return d
}

// short describes a manager tunnel in a few words.
func short(t *ipc.Tunnel) string {
	switch t.State {
	case ipc.StateStarting:
		return "connecting"
	case ipc.StateStopping:
		return "disconnecting"
	case ipc.StateError:
		return "failed"
	}
	if t.As == ipc.AsProxy {
		s := "proxy " + t.Listen
		if t.Waiting {
			s += ", waiting for a VPN"
		}
		return s
	}
	return "VPN"
}

func check(item *systray.MenuItem, on bool) {
	if on {
		item.Check()
	} else {
		item.Uncheck()
	}
}

func enable(item *systray.MenuItem, on bool) {
	if on {
		item.Enable()
	} else {
		item.Disable()
	}
}

func show(item *systray.MenuItem, on bool) {
	if on {
		item.Show()
	} else {
		item.Hide()
	}
}

// refreshLocked updates icon, tooltip, items and the window from the
// current state.
func (a *app) refreshLocked() {
	a.notifyWindow()
	if a.summaryMI == nil {
		return
	}
	st := a.status
	connected := a.link == linkConnected

	icon, summary := "down", ""
	switch a.link {
	case linkConnecting:
		summary = "Connecting to the SplitWire manager..."
	case linkMissing:
		summary = "SplitWire is not set up"
	case linkFailed:
		icon, summary = "error", "Manager unavailable: "+truncate(a.linkErr, 60)
	case linkConnected:
		var parts []string
		busy, failed, up := false, false, false
		for i := range st.Tunnels {
			t := &st.Tunnels[i]
			parts = append(parts, t.Name+" "+short(t))
			switch t.State {
			case ipc.StateStarting, ipc.StateStopping:
				busy = true
			case ipc.StateError:
				failed = true
			case ipc.StateUp:
				up = true
			}
		}
		switch {
		case failed:
			icon = "error"
		case busy:
			icon = "busy"
		case up:
			icon = "up"
		}
		summary = strings.Join(parts, ", ")
		if summary == "" {
			summary = "Not connected"
		}
	}
	systray.SetIcon(a.icons[icon])
	systray.SetTooltip(truncate("SplitWire: "+summary, 120))
	a.summaryMI.SetTitle(truncate(summary, 100))

	vpnName, proxies := "", 0
	for name, m := range a.menus {
		var t *ipc.Tunnel
		if connected {
			t = st.Find(name)
		}
		a.refreshTunnel(name, m, t, a.files[name], connected)
		if t.Running() && t.As == ipc.AsVPN {
			vpnName = name
		}
		if t.Running() && t.As == ipc.AsProxy {
			proxies++
		}
	}
	if vpnName != "" {
		a.vpnMI.SetTitle("VPN: " + vpnName)
	} else {
		a.vpnMI.SetTitle("VPN: off")
	}
	check(a.vpnOffMI, vpnName == "")
	enable(a.vpnOffMI, connected)
	if proxies > 0 {
		a.proxiesMI.SetTitle("Proxies: " + fmt.Sprint(proxies) + " running")
	} else {
		a.proxiesMI.SetTitle("Proxies")
	}

	show(a.downAllMI, connected && len(st.Tunnels) > 0)
	enable(a.bootMI, connected)
	check(a.bootMI, connected && st.Boot)
	show(a.setupMI, a.link == linkMissing || a.link == linkFailed)
	show(a.loginMI, a.link != linkMissing)
	show(a.uninstallMI, a.link != linkMissing)
}

func (a *app) refreshTunnel(name string, m *tunnelMenu, t *ipc.Tunnel, f tunnelFile, connected bool) {
	// Top section: live state of a running or failed tunnel.
	switch {
	case t != nil && t.State == ipc.StateError:
		m.status.SetTitle(name + " failed: " + truncate(t.Error, 80))
		m.status.Show()
	case t != nil && t.State == ipc.StateUp && len(t.Peers) > 0:
		p := t.Peers[0]
		m.status.SetTitle(fmt.Sprintf("%s (%s): handshake %s, received %s, sent %s", name, short(t),
			stats.Ago(p.LastHandshake), stats.Bytes(p.RxBytes), stats.Bytes(p.TxBytes)))
		m.status.Show()
	case t != nil:
		m.status.SetTitle(name + ": " + short(t))
		m.status.Show()
	default:
		m.status.Hide()
	}
	show(m.apply, t != nil && t.State == ipc.StateUp && f.hash != "" && f.hash != t.ConfigHash)

	// VPN and Proxies submenus.
	vpnTitle, proxyTitle := name, name
	if f.cfg != nil {
		vpnTitle += "  -  " + vpnDetail(f.cfg)
		proxyTitle += "  -  " + proxyDetail(f.cfg)
	} else {
		vpnTitle += "  -  configuration problem"
		proxyTitle += "  -  configuration problem"
	}
	running := t.Running()
	switch {
	case running && t.As == ipc.AsProxy:
		vpnTitle += "  (proxy now)"
	case running && t.As == ipc.AsVPN:
		proxyTitle += "  (VPN now)"
	}
	if t != nil && t.State != ipc.StateUp {
		state := " (" + short(t) + ")"
		if t.As == ipc.AsVPN {
			vpnTitle += state
		} else {
			proxyTitle += state
		}
	}
	m.vpn.SetTitle(vpnTitle)
	m.proxy.SetTitle(proxyTitle)
	check(m.vpn, running && t.As == ipc.AsVPN)
	check(m.proxy, running && t.As == ipc.AsProxy)
	usable := connected && f.error == ""
	enable(m.vpn, usable || (running && t.As == ipc.AsVPN))
	enable(m.proxy, usable || (running && t.As == ipc.AsProxy))

}

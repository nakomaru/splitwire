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
	// In the Split VPN, VPNs and Proxies submenus.
	split, vpn, proxy *systray.MenuItem
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

	a.onClick(systray.AddMenuItem("Open "+appTitle(), "Tunnels, their apps and settings"), gen, a.openWindow)
	a.splitMI = systray.AddMenuItem("Split VPN", "One tunnel carries the apps its Mode picks")
	a.splitOffMI = a.splitMI.AddSubMenuItemCheckbox("Off", "", true)
	a.onClick(a.splitOffMI, gen, a.splitOff)
	a.vpnsMI = systray.AddMenuItem("VPNs", "Any number of tunnels, each carrying its AllowedIPs for every app")
	a.proxiesMI = systray.AddMenuItem("Proxies", "Any number of tunnels serve local SOCKS5 and HTTP proxies")
	if len(a.names) == 0 {
		a.splitMI.AddSubMenuItem("No tunnels yet", "").Disable()
		a.vpnsMI.AddSubMenuItem("No tunnels yet", "").Disable()
		a.proxiesMI.AddSubMenuItem("No tunnels yet", "").Disable()
	}
	for _, name := range a.names {
		name := name
		m := a.menus[name]
		m.split = a.splitMI.AddSubMenuItemCheckbox(name, "", false)
		a.onClick(m.split, gen, func() { a.toggle(name, ipc.AsSplit) })
		m.vpn = a.vpnsMI.AddSubMenuItemCheckbox(name, "", false)
		a.onClick(m.vpn, gen, func() { a.toggle(name, ipc.AsVPN) })
		m.proxy = a.proxiesMI.AddSubMenuItemCheckbox(name, "", false)
		a.onClick(m.proxy, gen, func() { a.toggle(name, ipc.AsProxy) })
	}
	systray.AddSeparator()

	a.downAllMI = systray.AddMenuItem("Disconnect all", "")
	a.onClick(a.downAllMI, gen, func() { a.stop("") })
	a.bootMI = systray.AddMenuItemCheckbox("Reconnect tunnels when Windows starts", "Brings back running tunnels before anyone signs in", false)
	a.onClick(a.bootMI, gen, a.toggleBoot)
	a.loginMI = systray.AddMenuItemCheckbox("Start SplitWire at sign-in", "", runAtLogin())
	a.onClick(a.loginMI, gen, a.toggleLogin)
	systray.AddSeparator()
	a.onClick(systray.AddMenuItem("Show manager log", ""), gen, a.showLog)
	a.updateMI = systray.AddMenuItem(updateTitle(nil), "Install the newest release of SplitWire")
	a.onClick(a.updateMI, gen, a.updateApp)
	a.setupMI = systray.AddMenuItem("Set up SplitWire (administrator)...", "Install SplitWire and its background service")
	a.setupMI.Hide()
	a.onClick(a.setupMI, gen, a.setup)
	a.uninstallMI = systray.AddMenuItem("Uninstall SplitWire...", "Remove everything SplitWire installed")
	a.onClick(a.uninstallMI, gen, a.uninstall)
	a.onClick(systray.AddMenuItem("Close SplitWire (tunnels stay connected)", "Close the app; running tunnels stay up"), gen, systray.Quit)

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

// routeDetail describes the addresses a configuration carries as a VPN.
func routeDetail(c *config.Config) string {
	if c.HasDefaultRoute() {
		return "all addresses"
	}
	var ranges []string
	for _, p := range c.WG.Peers {
		for _, ip := range p.AllowedIPs {
			ranges = append(ranges, ip.String())
		}
	}
	switch len(ranges) {
	case 0:
		return "no addresses"
	case 1:
		return ranges[0]
	}
	return fmt.Sprintf("%s and %d more", ranges[0], len(ranges)-1)
}

// splitDetail describes the apps a configuration picks as the Split VPN.
func splitDetail(c *config.Config) string {
	if c.Mode == config.ModeFull {
		return "pick Include or Exclude first"
	}
	return c.Mode.String() + ", " + plural(len(c.Apps), "app")
}

// offDetail describes a configuration that is not running.
func offDetail(c *config.Config) string {
	if c.Mode != config.ModeFull {
		return splitDetail(c)
	}
	return routeDetail(c)
}

// proxyDetail describes where a configuration's proxy listens.
func proxyDetail(c *config.Config) string {
	if c.Proxy.IsValid() {
		return c.Proxy.String()
	}
	return fmt.Sprintf("port picked from %d on first use", userconf.FirstProxyPort)
}

// roleName names a way of running a tunnel.
func roleName(as string) string {
	switch as {
	case ipc.AsSplit:
		return "Split VPN"
	case ipc.AsVPN:
		return "VPN"
	}
	return "proxy"
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
		return "proxy " + t.Listen
	}
	return roleName(t.As)
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

	splitName, vpns, proxies := "", 0, 0
	for name, m := range a.menus {
		var t *ipc.Tunnel
		if connected {
			t = st.Find(name)
		}
		a.refreshTunnel(name, m, t, a.files[name], connected)
		if !t.Running() {
			continue
		}
		switch t.As {
		case ipc.AsSplit:
			splitName = name
		case ipc.AsVPN:
			vpns++
		case ipc.AsProxy:
			proxies++
		}
	}
	if splitName != "" {
		a.splitMI.SetTitle("Split VPN: " + splitName)
	} else {
		a.splitMI.SetTitle("Split VPN: off")
	}
	check(a.splitOffMI, splitName == "")
	enable(a.splitOffMI, connected)
	if vpns > 0 {
		a.vpnsMI.SetTitle("VPNs: " + fmt.Sprint(vpns) + " running")
	} else {
		a.vpnsMI.SetTitle("VPNs")
	}
	if proxies > 0 {
		a.proxiesMI.SetTitle("Proxies: " + fmt.Sprint(proxies) + " running")
	} else {
		a.proxiesMI.SetTitle("Proxies")
	}

	show(a.downAllMI, connected && len(st.Tunnels) > 0)
	enable(a.bootMI, connected)
	check(a.bootMI, connected && st.Boot)
	a.updateMI.SetTitle(updateTitle(a.latest))
	show(a.updateMI, a.link != linkMissing)
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

	// Split VPN, VPNs and Proxies submenus: each shows the tunnel with what it
	// does that way, and where it runs now when it runs another way.
	running := t.Running()
	items := []struct {
		item *systray.MenuItem
		as   string
		ok   bool
	}{
		{m.split, ipc.AsSplit, f.cfg != nil && f.cfg.Mode != config.ModeFull},
		{m.vpn, ipc.AsVPN, true},
		{m.proxy, ipc.AsProxy, true},
	}
	for i := range items {
		it := &items[i]
		title := name
		switch {
		case f.cfg == nil:
			title += "  -  configuration problem"
		case it.as == ipc.AsSplit:
			title += "  -  " + splitDetail(f.cfg)
		case it.as == ipc.AsVPN:
			title += "  -  " + routeDetail(f.cfg)
		default:
			title += "  -  " + proxyDetail(f.cfg)
		}
		switch {
		case running && t.As != it.as:
			title += "  (" + roleName(t.As) + " now)"
		case t != nil && t.State != ipc.StateUp && t.As == it.as:
			title += " (" + short(t) + ")"
		}
		this := running && t.As == it.as
		it.item.SetTitle(title)
		check(it.item, this)
		enable(it.item, connected && f.error == "" && it.ok || this)
	}
}

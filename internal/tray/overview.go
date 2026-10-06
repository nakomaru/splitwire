package tray

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"splitwire/internal/config"
	"splitwire/internal/ipc"
	"splitwire/internal/settings"
)

// The Overview page, the first row of the tunnel list, shows where traffic
// goes and holds the machine-wide settings: the kill switch, its local
// network exception, the DNS restriction and the Always direct list.

// routeRow is one line of where traffic goes.
type routeRow struct {
	what, where string
}

// overviewControls are the Overview page's controls.
type overviewControls struct {
	hRoutes, routeList                           *control
	hSwitches, ovKill, ovLAN, ovDNS              *control
	hDirect, directList, directAdd, directRemove *control
	directHint                                   *control
	routes                                       []routeRow
	direct                                       []string
}

func (w *window) addOverview(f *form) {
	o := &w.ov
	o.hRoutes = f.add(&control{kind: kindLabel, font: fontSemibold, text: "Where traffic goes"})
	o.routeList = f.addList(&control{itemHeight: 36}, 0)
	o.routeList.drawItem = w.drawRoute
	o.hSwitches = f.add(&control{kind: kindLabel, font: fontSemibold, text: "Protection"})
	o.ovKill = f.add(&control{kind: kindCheck, text: "Kill switch"})
	f.setTip(o.ovKill, "While a VPN carries every address, blocks traffic outside the tunnels, so nothing "+
		"leaks if it drops. Always direct destinations stay allowed.")
	o.ovLAN = f.add(&control{kind: kindCheck, text: "Allow the local network"})
	o.ovDNS = f.add(&control{kind: kindCheck, text: "Use only the tunnels' DNS servers"})
	f.setTip(o.ovDNS, "While a tunnel sets DNS servers, blocks every other DNS server, so name lookups "+
		"stay inside the tunnels.")
	o.hDirect = f.add(&control{kind: kindLabel, font: fontSemibold, text: "Always direct"})
	o.directList = f.addList(&control{itemHeight: 36, empty: "Nothing yet."}, lbsExtendedSel)
	o.directList.drawItem = w.drawDirect
	o.directAdd = f.add(&control{kind: kindButton, text: "Add", glyph: glyphAdd})
	o.directRemove = f.add(&control{kind: kindButton, text: "Remove", glyph: glyphDelete})
	o.directHint = f.add(&control{kind: kindLabel, color: labelSubtle,
		text: "Never through a VPN, except for an include mode Split VPN's apps."})
}

// layoutOverview places the Overview page between y and bottom: where
// traffic goes, the protections, then the Always direct list.
func (w *window) layoutOverview(x0, x1, y, bottom int32) {
	f := w.f
	o := &w.ov
	s := f.px
	bh := s(32)
	head := func(c *control) {
		f.place(c, rect{x0, y, x1, y + s(22)})
		y += s(22) + s(8)
	}
	fixed := 3*(s(22)+s(8)) + 2*s(30) + s(16) + s(16) + bh + s(10)
	lists := max(bottom-y-fixed, s(120))
	routesH := lists * 45 / 100

	head(o.hRoutes)
	f.place(o.routeList, rect{x0, y, x1, y + routesH})
	y += routesH + s(16)

	head(o.hSwitches)
	kw := f.toggleWidth(o.ovKill)
	f.place(o.ovKill, rect{x0, y, x0 + kw, y + s(28)})
	f.place(o.ovLAN, rect{x0 + kw + s(24), y, x0 + kw + s(24) + f.toggleWidth(o.ovLAN), y + s(28)})
	y += s(30)
	f.place(o.ovDNS, rect{x0, y, x0 + f.toggleWidth(o.ovDNS), y + s(28)})
	y += s(30) + s(16)

	head(o.hDirect)
	f.place(o.directList, rect{x0, y, x1, bottom - bh - s(10)})
	aw := f.buttonWidth(o.directAdd)
	rw := f.buttonWidth(o.directRemove)
	f.place(o.directAdd, rect{x0, bottom - bh, x0 + aw, bottom})
	f.place(o.directRemove, rect{x0 + aw + s(8), bottom - bh, x0 + aw + s(8) + rw, bottom})
	f.place(o.directHint, rect{x0 + aw + rw + s(24), bottom - bh, x1, bottom})
}

// showOverview shows or hides the Overview page.
func (w *window) showOverview(on bool) {
	o := &w.ov
	for _, c := range []*control{o.hRoutes, o.routeList, o.hSwitches, o.ovKill, o.ovLAN, o.ovDNS,
		o.hDirect, o.directList, o.directAdd, o.directRemove, o.directHint} {
		w.f.show(c, on)
	}
}

// updateOverview fills the Overview page from the app's state.
func (w *window) updateOverview() {
	f := w.f
	o := &w.ov
	connected := w.snap.link == linkConnected
	set := w.snap.status.Settings

	rows := w.routeRows()
	if !slices.Equal(rows, o.routes) {
		o.routes = rows
		items := make([]string, len(rows))
		for i, r := range rows {
			items[i] = r.what
		}
		f.listSet(o.routeList, items)
	}
	o.routeList.empty = ""
	if !connected {
		o.routeList.empty = w.statusText(nil, tunnelFile{})
	}

	f.setOn(o.ovKill, set.KillSwitch)
	f.enable(o.ovKill, connected)
	f.setOn(o.ovLAN, set.AllowLAN)
	f.enable(o.ovLAN, connected && set.KillSwitch)
	lanTip := "Lets apps reach private addresses, such as the router, printers and other computers at " +
		"home, past the kill switch."
	if !set.KillSwitch {
		lanTip = "Applies while the kill switch is on. " + lanTip
	}
	if o.ovLAN.tip != lanTip {
		f.setTip(o.ovLAN, lanTip)
	}
	f.setOn(o.ovDNS, set.StrictDNS)
	f.enable(o.ovDNS, connected)

	if !slices.Equal(set.Direct, o.direct) {
		o.direct = slices.Clone(set.Direct)
		f.listSet(o.directList, o.direct)
	}
	f.enable(o.directAdd, connected)
	f.enable(o.directRemove, connected && len(f.listSelected(o.directList)) > 0)
}

// overviewStatus sums up the running tunnels in a line.
func (w *window) overviewStatus() string {
	if w.snap.link != linkConnected {
		return w.statusText(nil, tunnelFile{})
	}
	var split string
	var vpns, proxies []string
	for _, t := range w.snap.status.Tunnels {
		if !t.Running() {
			continue
		}
		switch t.As {
		case ipc.AsSplit:
			split = t.Name
		case ipc.AsVPN:
			vpns = append(vpns, t.Name)
		case ipc.AsProxy:
			proxies = append(proxies, t.Name)
		}
	}
	var parts []string
	if split != "" {
		parts = append(parts, "Split VPN: "+split)
	}
	if len(vpns) > 0 {
		parts = append(parts, "VPNs: "+strings.Join(vpns, ", "))
	}
	if len(proxies) > 0 {
		parts = append(parts, "Proxies: "+strings.Join(proxies, ", "))
	}
	if len(parts) == 0 {
		return "Nothing connected. Every app connects directly."
	}
	return strings.Join(parts, " · ")
}

// routeRows lists where traffic goes: the Split VPN's apps, each VPN's
// addresses, the Always direct list, everything else, and the proxies.
func (w *window) routeRows() []routeRow {
	if w.snap.link != linkConnected {
		return nil
	}
	tunnels := slices.Clone(w.snap.status.Tunnels)
	sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].Name < tunnels[j].Name })
	var split, vpns, proxies []routeRow
	everything := routeRow{what: "Everything else", where: "Direct"}
	for _, t := range tunnels {
		if !t.Running() {
			continue
		}
		c := w.snap.files[t.Name].cfg
		where := t.Name + " · " + roleName(t.As)
		switch t.As {
		case ipc.AsSplit:
			what := plural(t.Apps, "app")
			if c != nil {
				what = appNames(c)
			}
			if t.Mode == config.ModeExclude.String() {
				what = "Every app except " + what
			}
			split = append(split, routeRow{what, where})
		case ipc.AsVPN:
			if c != nil && c.HasDefaultRoute() {
				everything.where = where
				continue
			}
			what := "its addresses"
			if c != nil {
				what = strings.Join(allowedIPs(c), ", ")
			}
			vpns = append(vpns, routeRow{what, where})
		case ipc.AsProxy:
			proxies = append(proxies, routeRow{"Apps set to the proxy " + t.Listen, where})
		}
	}
	rows := append(split, vpns...)
	switch n := len(w.snap.status.Settings.Direct); n {
	case 0:
	case 1:
		rows = append(rows, routeRow{"1 Always direct entry", "Direct"})
	default:
		rows = append(rows, routeRow{fmt.Sprintf("%d Always direct entries", n), "Direct"})
	}
	rows = append(rows, everything)
	return append(rows, proxies...)
}

// appNames names a configuration's apps in a few words.
func appNames(c *config.Config) string {
	var names []string
	for _, a := range c.Apps {
		base := a[strings.LastIndexAny(a, `\/`)+1:]
		names = append(names, strings.TrimSuffix(base, ".exe"))
	}
	if len(names) > 3 {
		return fmt.Sprintf("%s and %d more", strings.Join(names[:3], ", "), len(names)-3)
	}
	return strings.Join(names, ", ")
}

func allowedIPs(c *config.Config) []string {
	var out []string
	for _, p := range c.WG.Peers {
		for _, ip := range p.AllowedIPs {
			out = append(out, ip.String())
		}
	}
	return out
}

func (w *window) drawRoute(dc uintptr, i int, r rect, selected bool) {
	if i >= len(w.ov.routes) {
		return
	}
	f := w.f
	row := w.ov.routes[i]
	whereW, _ := f.measure(row.where, f.fonts[fontNormal])
	whereW = min(whereW, (r.right-r.left)/2)
	right := r.right - f.px(12)
	drawText(dc, row.where, rect{right - whereW, r.top, right, r.bottom}, f.fonts[fontNormal], f.col.subtext, dtSingleLine|dtVCenter|dtEndEllipsis)
	drawText(dc, row.what, rect{r.left + f.px(12), r.top, right - whereW - f.px(16), r.bottom}, f.fonts[fontNormal], f.col.text, dtSingleLine|dtVCenter|dtEndEllipsis)
}

func (w *window) drawDirect(dc uintptr, i int, r rect, selected bool) {
	if i >= len(w.ov.direct) {
		return
	}
	f := w.f
	e := w.ov.direct[i]
	kind := "host name, looked up when a tunnel connects"
	if d, err := config.ParseDirect([]string{e}); err == nil && len(d.Prefixes) > 0 {
		kind = "address range"
		if p := d.Prefixes[0]; p.IsSingleIP() {
			kind = "address"
		}
	}
	kw, _ := f.measure(kind, f.fonts[fontNormal])
	right := r.right - f.px(12)
	drawText(dc, kind, rect{right - kw, r.top, right, r.bottom}, f.fonts[fontNormal], f.col.subtext, dtSingleLine|dtVCenter)
	drawText(dc, e, rect{r.left + f.px(12), r.top, right - kw - f.px(16), r.bottom}, f.fonts[fontNormal], f.col.text, dtSingleLine|dtVCenter|dtEndEllipsis)
}

// overviewCommand handles a click on an Overview control, and reports
// whether c was one.
func (w *window) overviewCommand(c *control, code uint16) bool {
	o := &w.ov
	if c == o.directList {
		if code == lbnSelChange {
			w.f.enable(o.directRemove, len(w.f.listSelected(o.directList)) > 0)
		}
		return true
	}
	if code != bnClicked {
		return false
	}
	switch c {
	case o.ovKill:
		on := !c.on
		go w.changeSettings(func(s *settings.Settings) { s.KillSwitch = on })
	case o.ovLAN:
		on := !c.on
		go w.changeSettings(func(s *settings.Settings) { s.AllowLAN = on })
	case o.ovDNS:
		on := !c.on
		go w.changeSettings(func(s *settings.Settings) { s.StrictDNS = on })
	case o.directAdd:
		w.addDirect()
	case o.directRemove:
		var gone []string
		for _, i := range w.f.listSelected(o.directList) {
			if i < len(o.direct) {
				gone = append(gone, o.direct[i])
			}
		}
		go w.changeSettings(func(s *settings.Settings) {
			s.Direct = slices.DeleteFunc(s.Direct, func(e string) bool { return slices.Contains(gone, e) })
		})
	default:
		return false
	}
	return true
}

// addDirect asks for an Always direct entry and adds it.
func (w *window) addDirect() {
	have := w.snap.status.Settings.Direct
	entry, ok := askText(w.f.hwnd, "Add to Always direct",
		"An address range, address or host name whose traffic never goes through a VPN, such as "+
			"203.0.113.0/24 or vpn.office.example:", "", func(s string) error {
			if s == "" {
				return errors.New("Enter an address range, address or host name.")
			}
			if slices.Contains(have, s) {
				return fmt.Errorf("%s is already on the list.", s)
			}
			_, err := config.ParseDirect([]string{s})
			return err
		})
	if ok {
		go w.changeSettings(func(s *settings.Settings) { s.Direct = append(s.Direct, entry) })
	}
}

// changeSettings applies change to the machine-wide settings through the
// manager.
func (w *window) changeSettings(change func(*settings.Settings)) {
	w.a.mu.Lock()
	s := w.a.status.Settings
	w.a.mu.Unlock()
	s.Direct = slices.Clone(s.Direct)
	change(&s)
	if _, err := call(ipc.Request{Op: ipc.OpSettings, Settings: &s}); err != nil {
		errorBox("Could not change the settings:\n\n%v", err)
	}
}

// drawOverviewRow draws the tunnel list's Overview row: a globe, and how
// many tunnels run.
func (w *window) drawOverviewRow(dc uintptr, r rect) {
	f := w.f
	running := 0
	if w.snap.link == linkConnected {
		for _, t := range w.snap.status.Tunnels {
			if t.Running() {
				running++
			}
		}
	}
	line := "Nothing connected"
	if running > 0 {
		line = plural(running, "tunnel") + " connected"
	}
	f.drawGlyph(dc, glyphGlobe, 12, rect{r.left + f.px(12), r.top, r.left + f.px(28), r.bottom}, f.col.text)
	x := r.left + f.px(36)
	drawText(dc, "Overview", rect{x, r.top + f.px(7), r.right - f.px(8), r.top + f.px(27)}, f.fonts[fontNormal], f.col.text, dtSingleLine|dtVCenter|dtEndEllipsis)
	drawText(dc, line, rect{x, r.top + f.px(26), r.right - f.px(8), r.bottom - f.px(6)}, f.fonts[fontNormal], f.col.subtext, dtSingleLine|dtVCenter|dtEndEllipsis)
}

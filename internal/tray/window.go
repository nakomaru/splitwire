package tray

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"splitwire/internal/apps"
	"splitwire/internal/config"
	"splitwire/internal/ipc"
	"splitwire/internal/stats"
	"splitwire/internal/userconf"
)

// wmRefresh tells the window that the app's state changed.
const wmRefresh = wmApp + 1

// Tabs of a tunnel.
const (
	tabVPN = iota
	tabProxy
	tabDetails
	tabText
	tabCount
)

// appEntry is an App setting as the window shows it.
type appEntry struct {
	raw  string
	name string
	// icon is the file whose icon the entry shows.
	icon string
	// note describes what the entry matches; warn marks a problem.
	note string
	warn bool
}

// snapshot is the app state the window shows.
type snapshot struct {
	names   []string
	files   map[string]tunnelFile
	status  ipc.Status
	link    int
	linkErr string
	traffic map[string]traffic
}

func (a *app) snapshot() snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := snapshot{names: append([]string(nil), a.names...), files: make(map[string]tunnelFile, len(a.files)),
		status: a.status, link: a.link, linkErr: a.linkErr, traffic: make(map[string]traffic, len(a.traffic))}
	for k, v := range a.files {
		s.files[k] = v
	}
	for k, v := range a.traffic {
		s.traffic[k] = traffic{since: v.since, samples: append([]sample(nil), v.samples...)}
	}
	return s
}

// window is the tunnels window: the list of tunnels, and the selected
// one's state, its settings as a VPN and as a proxy, its details and its
// text.
type window struct {
	f     *form
	a     *app
	icons iconCache
	snap  snapshot

	sel string
	tab int
	// The selected tunnel's file: its text as read, with \n line endings,
	// whether the file uses \r\n, and what it parses to.
	path    string
	text    string
	crlf    bool
	cfg     *config.Config
	cfgErr  error
	entries []appEntry
	// dirty reports that the editor holds unsaved changes; loading
	// suppresses change handling while the window fills the editor, and
	// coloring while it colors the text.
	dirty, loading, coloring bool
	// errLine is the editor's line with a problem, from 1, or 0.
	errLine int
	graph   rect

	list, add, del                           *control
	title, rename, status, banner, reconnect *control
	segOff, segSplit, segVPN, segProxy       *control
	tabs                                     [tabCount]*control
	problem                                  *control

	hSplit, splitOff, splitInclude, splitExclude  *control
	modeNote, appList, appAdd, appRemove, appHint *control

	portLabel, port, portNote, copyAddr, proxyHint *control

	editor, parse, revert, save *control

	det detailsControls
	ov  overviewControls
}

// windowCreating marks a.win while the window thread starts.
const windowCreating = ^uintptr(0)

// toggleWindow closes the tunnels window while it shows, and opens it
// otherwise. Closing asks about unsaved text first, as the close button does.
func (a *app) toggleWindow() {
	a.mu.Lock()
	hwnd := a.win
	a.mu.Unlock()
	if hwnd != 0 && hwnd != windowCreating {
		if iconic, _, _ := procIsIconic.Call(hwnd); iconic == 0 {
			postMessage(hwnd, wmClose)
			return
		}
	}
	a.openWindow()
}

// openWindow shows the tunnels window, creating it on its own thread.
func (a *app) openWindow() {
	a.mu.Lock()
	if a.win != 0 {
		hwnd := a.win
		a.mu.Unlock()
		if hwnd == windowCreating {
			return
		}
		if iconic, _, _ := procIsIconic.Call(hwnd); iconic != 0 {
			procShowWindow.Call(hwnd, swRestore)
		}
		procSetForegroundWindow.Call(hwnd)
		return
	}
	a.win = windowCreating
	a.mu.Unlock()
	onUIThread(func() {
		w := newWindow(a)
		a.mu.Lock()
		a.win = w.f.hwnd
		a.mu.Unlock()
		procShowWindow.Call(w.f.hwnd, swShowNormal)
		procSetForegroundWindow.Call(w.f.hwnd)
		runForms(nil)
	})
}

// showInWindow selects the tunnel once the window learns of it.
func (a *app) showInWindow(name string) {
	a.mu.Lock()
	a.winSelect = name
	a.notifyWindow()
	a.mu.Unlock()
}

// notifyWindow has the window refresh. The caller holds a.mu.
func (a *app) notifyWindow() {
	if a.win != 0 && a.win != windowCreating {
		postMessage(a.win, wmRefresh)
	}
}

func newWindow(a *app) *window {
	w := &window{a: a, icons: iconCache{}}
	f := &form{minW: 760, minH: 600}
	w.f = f
	f.layout = w.layout
	f.paint = w.paint
	f.command = w.command
	f.enter = w.enter
	f.save = func() {
		switch {
		case w.tab == tabText && w.dirty:
			w.saveText()
		case w.tab == tabDetails && w.f.enabled(w.det.save):
			w.saveDetails()
		}
	}
	f.key = w.key
	f.menuAt = w.contextMenu
	f.close = func() {
		if w.confirmLeave() {
			procDestroyWindow.Call(f.hwnd)
		}
	}
	f.destroyed = func() {
		w.icons.free()
		a.mu.Lock()
		a.win = 0
		a.mu.Unlock()
		procPostQuitMessage.Call(0)
	}
	f.message = func(msg, wparam, lparam uintptr) (uintptr, bool) {
		switch msg {
		case wmRefresh:
			w.refresh()
			return 0, true
		case wmProbed:
			w.probed()
			return 0, true
		}
		return 0, false
	}
	f.restyle = func() {
		if w.editor != nil {
			w.highlight()
		}
	}
	newForm(f, appTitle(), 0, wsOverlappedWindow, 920, 700)

	w.list = f.addList(&control{itemHeight: 52, empty: "No tunnels yet. Add one below."}, 0)
	w.list.drawItem = w.drawTunnel
	w.add = f.add(&control{kind: kindButton, text: "Add", glyph: glyphAdd, menu: true})
	w.del = f.add(&control{kind: kindButton, text: "Delete", glyph: glyphDelete})

	w.title = f.add(&control{kind: kindLabel, font: fontTitle})
	w.rename = f.add(&control{kind: kindIcon, glyph: glyphEdit})
	w.status = f.add(&control{kind: kindLabel, color: labelSubtle})
	w.banner = f.add(&control{kind: kindLabel, color: labelCaution, text: "Edited since it connected. Reconnect to use the changes."})
	w.reconnect = f.add(&control{kind: kindButton, text: "Reconnect"})
	w.segOff = f.add(&control{kind: kindButton, text: "Off"})
	w.segSplit = f.add(&control{kind: kindButton, text: "Split VPN"})
	w.segVPN = f.add(&control{kind: kindButton, text: "VPN"})
	w.segProxy = f.add(&control{kind: kindButton, text: "Proxy"})
	for i, name := range []string{"VPN", "Proxy", "Details", "Text"} {
		w.tabs[i] = f.add(&control{kind: kindTab, text: name})
	}
	w.problem = f.add(&control{kind: kindLabel, color: labelError, wrap: true})

	w.hSplit = f.add(&control{kind: kindLabel, font: fontSemibold, text: "Split tunneling"})
	w.splitOff = f.add(&control{kind: kindButton, text: "Off"})
	w.splitInclude = f.add(&control{kind: kindButton, text: "Include"})
	w.splitExclude = f.add(&control{kind: kindButton, text: "Exclude"})
	w.modeNote = f.add(&control{kind: kindLabel, color: labelSubtle})
	w.appList = f.addList(&control{itemHeight: 46}, lbsExtendedSel)
	w.appList.drawItem = w.drawApp
	w.appAdd = f.add(&control{kind: kindButton, text: "Add apps", glyph: glyphAdd})
	w.appRemove = f.add(&control{kind: kindButton, text: "Remove", glyph: glyphDelete})
	w.appHint = f.add(&control{kind: kindLabel, color: labelSubtle})

	w.portLabel = f.add(&control{kind: kindLabel, text: "Port"})
	w.port = f.addEdit(&control{}, esNumber)
	w.portNote = f.add(&control{kind: kindLabel, color: labelSubtle})
	w.copyAddr = f.add(&control{kind: kindButton, text: "Copy address", glyph: glyphCopy})
	w.proxyHint = f.add(&control{kind: kindLabel, color: labelSubtle, wrap: true,
		text: "Apps use the tunnel through their SOCKS5 or HTTP proxy setting, pointed at this address. " +
			"Its packets go straight to its server, never through a VPN."})

	w.addDetails(f)
	w.addOverview(f)

	w.editor = f.addRich(&control{font: fontMono}, esMultiline|esAutoVScroll|wsVScroll|wsHScroll|esWantReturn|esNoHideSel)
	w.parse = f.add(&control{kind: kindLabel})
	w.revert = f.add(&control{kind: kindButton, text: "Revert"})
	w.save = f.add(&control{kind: kindButton, text: "Save", primary: true})
	cue, _ := windows.UTF16PtrFromString("On first use")
	procSendMessageW.Call(w.port.hwnd, emSetCueBanner, 1, uintptr(unsafe.Pointer(cue)))
	procSendMessageW.Call(w.port.hwnd, emLimitText, 5, 0)

	f.ready = true
	w.refresh()
	w.showTab(tabVPN)
	w.relayout()
	return w
}

// Layout

func clamp(v, lo, hi int32) int32 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (w *window) layout(cw, ch int32) {
	f := w.f
	s := f.px
	m := s(20)
	lw := clamp(cw*28/100, s(220), s(320))
	bh := s(32)

	// Left: the tunnels.
	by := ch - m - bh
	f.place(w.list, rect{m, m, m + lw, by - s(8)})
	half := (lw - s(8)) / 2
	f.place(w.add, rect{m, by, m + half, by + bh})
	f.place(w.del, rect{m + half + s(8), by, m + lw, by + bh})

	// Right: the selected tunnel.
	x0, x1 := m+lw+s(28), cw-m
	y := m
	segs := []*control{w.segOff, w.segSplit, w.segVPN, w.segProxy}
	segW, gap := s(76), s(4)
	for _, c := range segs {
		segW = max(segW, f.buttonWidth(c))
	}
	segX := x1 - int32(len(segs))*segW - int32(len(segs)-1)*gap
	for i, c := range segs {
		x := segX + int32(i)*(segW+gap)
		f.place(c, rect{x, y, x + segW, y + bh})
	}
	tw, _ := f.measure(w.title.text, f.fonts[fontTitle])
	titleRight := x0 + tw
	if limit := segX - s(48); titleRight > limit {
		titleRight = limit
	}
	f.place(w.title, rect{x0, y - s(2), titleRight, y + bh})
	f.place(w.rename, rect{titleRight + s(6), y + s(2), titleRight + s(34), y + bh - s(2)})
	y += bh + s(4)
	f.place(w.status, rect{x0, y, x1, y + s(20)})
	y += s(28)
	w.layoutOverview(x0, x1, y+s(4), by+bh)
	if !w.reconnect.hidden {
		rw := f.buttonWidth(w.reconnect)
		f.place(w.reconnect, rect{x1 - rw, y, x1, y + bh})
		f.place(w.banner, rect{x0, y, x1 - rw - s(12), y + bh})
		y += bh + s(12)
	}
	w.graph = rect{}
	if w.graphShown() {
		w.graph = rect{x0, y, x1, y + s(104)}
		y += s(104) + s(12)
	}
	x := x0
	for _, c := range w.tabs {
		tw, _ := f.measure(c.text, f.fonts[fontSemibold])
		f.place(c, rect{x, y, x + tw + s(28), y + s(36)})
		x += tw + s(28)
	}
	y += s(36) + s(14)

	f.place(w.problem, rect{x0, y, x1, y + f.measureWrapped(w.problem.text, f.fonts[fontNormal], x1-x0)})

	w.layoutVPN(x0, x1, y, by+bh)
	w.layoutProxy(x0, x1, y)
	w.layoutDetails(x0, x1, y, by-s(10), by)

	// Text tab.
	f.place(w.editor, rect{x0, y, x1, by - s(10)})
	sw := f.buttonWidth(w.save)
	vw := f.buttonWidth(w.revert)
	f.place(w.save, rect{x1 - sw, by, x1, by + bh})
	f.place(w.revert, rect{x1 - sw - s(8) - vw, by, x1 - sw - s(8), by + bh})
	f.place(w.parse, rect{x0, by, x1 - sw - vw - s(24), by + bh})
}

// layoutVPN places the VPN tab between y and bottom: split tunneling at
// the top and the apps below.
func (w *window) layoutVPN(x0, x1, y, bottom int32) {
	f := w.f
	s := f.px
	bh := s(32)
	hw, _ := f.measure(w.hSplit.text, f.fonts[fontSemibold])
	f.place(w.hSplit, rect{x0, y, x0 + hw, y + bh})
	segs := []*control{w.splitOff, w.splitInclude, w.splitExclude}
	var segW int32
	for _, c := range segs {
		segW = max(segW, f.buttonWidth(c))
	}
	sx := x0 + hw + s(20)
	for i, c := range segs {
		x := sx + int32(i)*(segW+s(4))
		f.place(c, rect{x, y, x + segW, y + bh})
	}
	y += bh + s(6)
	f.place(w.modeNote, rect{x0, y, x1, y + s(20)})
	y += s(20) + s(10)

	aw := f.buttonWidth(w.appAdd)
	rw := f.buttonWidth(w.appRemove)
	f.place(w.appAdd, rect{x0, bottom - bh, x0 + aw, bottom})
	f.place(w.appRemove, rect{x0 + aw + s(8), bottom - bh, x0 + aw + s(8) + rw, bottom})
	f.place(w.appHint, rect{x0 + aw + rw + s(24), bottom - bh, x1, bottom})
	f.place(w.appList, rect{x0, y, x1, bottom - bh - s(10)})
}

func (w *window) layoutProxy(x0, x1, y int32) {
	f := w.f
	s := f.px
	bh := s(32)
	lblW := s(96)
	f.place(w.portLabel, rect{x0, y, x0 + lblW, y + bh})
	f.place(w.port, rect{x0 + lblW, y, x0 + lblW + s(120), y + bh})
	cw := f.buttonWidth(w.copyAddr)
	f.place(w.copyAddr, rect{x1 - cw, y, x1, y + bh})
	f.place(w.portNote, rect{x0 + lblW + s(132), y, x1 - cw - s(12), y + bh})
	y += bh + s(10)
	h := f.measureWrapped(w.proxyHint.text, f.fonts[fontNormal], x1-x0)
	f.place(w.proxyHint, rect{x0, y, x1, y + h})
}

// relayout lays the window out again after controls appear or vanish.
func (w *window) relayout() {
	var r rect
	procGetClientRect.Call(w.f.hwnd, uintptr(unsafe.Pointer(&r)))
	if r.right > 0 {
		w.layout(r.right, r.bottom)
		procInvalidateRect.Call(w.f.hwnd, 0, 0)
	}
}

// State

func (w *window) tunnel() *ipc.Tunnel {
	if w.snap.link != linkConnected {
		return nil
	}
	return w.snap.status.Find(w.sel)
}

func (w *window) graphShown() bool {
	t := w.tunnel()
	return t != nil && t.State == ipc.StateUp
}

// refresh takes in the app's state.
func (w *window) refresh() {
	old := w.snap
	w.snap = w.a.snapshot()
	w.a.mu.Lock()
	want := w.a.winSelect
	w.a.winSelect = ""
	w.a.mu.Unlock()

	if old.files == nil || strings.Join(old.names, "\x00") != strings.Join(w.snap.names, "\x00") {
		w.f.listSet(w.list, append([]string{"Overview"}, w.snap.names...))
	} else {
		w.f.invalidate(w.list)
	}
	name := w.sel
	if want != "" && w.has(want) && w.confirmLeave() {
		name = want
	}
	if !w.has(name) {
		name = ""
	}
	w.f.listSetCurSel(w.list, w.rowOf(name))
	if name != w.sel {
		w.sel = name
		w.load()
	} else if w.sel != "" && !w.dirty && !w.detailsDirty() {
		// The file may have changed on disk.
		if b, err := os.ReadFile(w.path); err == nil && normalize(string(b)) != w.text {
			w.load()
		}
	}
	w.update()
}

// overviewRow is the tunnel list's first row, the Overview page, which shows
// whenever no tunnel is selected.
const overviewRow = 0

// rowOf is the tunnel list row of the named tunnel, or the Overview's for "".
func (w *window) rowOf(name string) int {
	for i, n := range w.snap.names {
		if n == name {
			return i + 1
		}
	}
	return overviewRow
}

// nameAt is the tunnel at a tunnel list row, or "" for the Overview.
func (w *window) nameAt(row int) string {
	if row <= overviewRow || row > len(w.snap.names) {
		return ""
	}
	return w.snap.names[row-1]
}

func (w *window) has(name string) bool {
	for _, n := range w.snap.names {
		if n == name {
			return true
		}
	}
	return false
}

// normalize drops a byte order mark and makes every line end with \n.
func normalize(s string) string {
	s = strings.ReplaceAll(strings.TrimPrefix(s, "\uFEFF"), "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "\n")
}

// load reads the selected tunnel's file into the window.
func (w *window) load() {
	w.path, w.text, w.cfg, w.cfgErr, w.entries, w.dirty = "", "", nil, nil, nil, false
	if w.sel != "" {
		w.path, w.cfgErr = userconf.Resolve(w.sel)
		if w.cfgErr == nil {
			var b []byte
			if b, w.cfgErr = os.ReadFile(w.path); w.cfgErr == nil {
				w.crlf = strings.Contains(string(b), "\r\n")
				w.text = normalize(string(b))
				w.cfg, w.cfgErr = config.Parse(w.text, w.sel)
			}
		}
	}
	if w.cfg != nil {
		for _, raw := range w.cfg.Apps {
			w.entries = append(w.entries, describeApp(raw))
		}
	}
	items := make([]string, len(w.entries))
	for i, e := range w.entries {
		items[i] = e.raw
	}
	w.f.listSet(w.appList, items)

	w.loading = true
	w.f.setText(w.editor, strings.ReplaceAll(w.text, "\n", "\r\n"))
	w.loading = false
	w.checkText()

	port := ""
	if w.cfg != nil && w.cfg.Proxy.IsValid() {
		port = strconv.Itoa(int(w.cfg.Proxy.Port()))
	}
	if focus, _, _ := procGetFocus.Call(); focus != w.port.hwnd {
		w.f.setText(w.port, port)
	}
	w.loadDetails()
}

// describeApp finds what an App entry matches.
func describeApp(raw string) appEntry {
	e := appEntry{raw: raw}
	matches, err := config.ExpandApp(raw)
	base := raw[strings.LastIndexAny(raw, `\/`)+1:]
	switch {
	case err != nil:
		e.name, e.note, e.warn = base, err.Error(), true
	case strings.ContainsAny(raw, "*?["):
		e.name = strings.TrimSuffix(base, ".exe")
		if len(matches) > 0 {
			e.icon = matches[0]
			e.name = apps.DisplayName(matches[0])
		}
		switch len(matches) {
		case 0:
			e.note, e.warn = "matches no files", true
		case 1:
			e.note = "matches 1 file"
		default:
			e.note = fmt.Sprintf("matches %d files", len(matches))
		}
	default:
		e.icon = matches[0]
		if _, err := os.Stat(matches[0]); err != nil {
			e.name, e.note, e.warn = strings.TrimSuffix(base, ".exe"), "not found", true
		} else {
			e.name = apps.DisplayName(matches[0])
		}
	}
	return e
}

// update shows the selected tunnel's state and settings.
func (w *window) update() {
	f := w.f
	hasSel := w.sel != ""
	t := w.tunnel()
	file := w.snap.files[w.sel]
	running := t.Running()
	connected := w.snap.link == linkConnected

	title := w.sel
	if !hasSel {
		title = "Overview"
	}
	layoutChanged := w.title.text != title
	f.setText(w.title, title)
	w.status.color = labelSubtle
	if t != nil && t.State == ipc.StateError || file.error != "" && t == nil {
		w.status.color = labelError
	}
	if hasSel {
		f.setText(w.status, w.statusText(t, file))
	} else {
		f.setText(w.status, w.overviewStatus())
		w.updateOverview()
	}
	f.show(w.rename, hasSel)
	f.enable(w.del, hasSel)

	usable := connected && file.error == "" && hasSel
	picksApps := file.cfg != nil && file.cfg.Mode != config.ModeFull
	f.setOn(w.segOff, hasSel && !running)
	f.enable(w.segOff, connected && running)
	for _, seg := range []struct {
		c  *control
		as string
		ok bool
	}{{w.segSplit, ipc.AsSplit, picksApps}, {w.segVPN, ipc.AsVPN, true}, {w.segProxy, ipc.AsProxy, true}} {
		this := running && t.As == seg.as
		f.setOn(seg.c, this)
		f.enable(seg.c, usable && seg.ok || this)
	}
	splitTip := "Runs it for the apps on the VPN tab. One tunnel is the Split VPN at a time."
	if !picksApps {
		splitTip = "Pick Include or Exclude on the VPN tab to run it for chosen apps."
	}
	if w.segSplit.tip != splitTip {
		f.setTip(w.segSplit, splitTip)
	}
	for _, c := range []*control{w.segOff, w.segSplit, w.segVPN, w.segProxy} {
		f.show(c, hasSel)
	}

	stale := t != nil && t.State == ipc.StateUp && file.hash != "" && file.hash != t.ConfigHash
	if w.reconnect.hidden == stale || w.graph.empty() == w.graphShown() {
		layoutChanged = true
	}
	f.show(w.reconnect, stale)
	f.show(w.banner, stale)

	problem := ""
	if w.cfgErr != nil {
		problem = "This tunnel has a problem: " + w.cfgErr.Error() + "\n\nFix it on the Text tab."
	}
	if problem != w.problem.text {
		f.setText(w.problem, problem)
		layoutChanged = true
	}
	if c := w.cfg; c != nil {
		w.updateVPN(c)
		w.updateProxy(c)
	}
	if w.updateDetails() {
		layoutChanged = true
	}
	w.showTab(w.tab)
	if layoutChanged {
		w.relayout()
	} else if !w.graph.empty() {
		procInvalidateRect.Call(f.hwnd, uintptr(unsafe.Pointer(&w.graph)), 0)
	}
}

// updateVPN shows the tunnel's settings as a VPN.
func (w *window) updateVPN(c *config.Config) {
	f := w.f
	f.setOn(w.splitOff, c.Mode == config.ModeFull)
	f.setOn(w.splitInclude, c.Mode == config.ModeInclude)
	f.setOn(w.splitExclude, c.Mode == config.ModeExclude)
	hint := "Programs an app starts follow it."
	switch c.Mode {
	case config.ModeFull:
		f.setText(w.modeNote, "As a VPN, every app uses it for the addresses in AllowedIPs. "+
			"Include or Exclude lets it run as the Split VPN.")
		w.appList.empty = "Pick Include or Exclude to choose apps."
		if len(c.Apps) > 0 {
			hint = "Kept for Include and Exclude."
		}
	case config.ModeInclude:
		f.setText(w.modeNote, "As the Split VPN, only the apps below use it. As a VPN, every app does.")
		w.appList.empty = "No apps yet."
	case config.ModeExclude:
		f.setText(w.modeNote, "As the Split VPN, every app except the ones below uses it. As a VPN, every app does.")
		w.appList.empty = "No apps yet."
	}
	f.setText(w.appHint, hint)
	f.enable(w.appRemove, len(f.listSelected(w.appList)) > 0)
}

// updateProxy shows the tunnel's settings as a proxy.
func (w *window) updateProxy(c *config.Config) {
	f := w.f
	note := "Picks a free port from 1080 up"
	if c.Proxy.IsValid() {
		note = "Listens on " + c.Proxy.String()
	}
	f.setText(w.portNote, note)
	f.enable(w.copyAddr, c.Proxy.IsValid())
}

func (r rect) empty() bool { return r.right <= r.left || r.bottom <= r.top }

// statusText describes the tunnel's state in a line.
func (w *window) statusText(t *ipc.Tunnel, file tunnelFile) string {
	switch w.snap.link {
	case linkConnecting:
		return "Connecting to the SplitWire service..."
	case linkMissing:
		return "SplitWire is not set up. Set it up from the menu of its notification area icon."
	case linkFailed:
		return "The SplitWire service is unavailable: " + w.snap.linkErr
	}
	if t == nil {
		if file.error != "" {
			return "Off. It has a problem; see below."
		}
		if file.cfg != nil {
			return "Off. As a VPN: " + routeDetail(file.cfg) + "."
		}
		return "Off"
	}
	switch t.State {
	case ipc.StateStarting:
		return "Connecting..."
	case ipc.StateStopping:
		return "Disconnecting..."
	case ipc.StateError:
		return "Failed: " + t.Error
	}
	var parts []string
	switch t.As {
	case ipc.AsSplit:
		parts = append(parts, "Connected as the Split VPN")
	case ipc.AsVPN:
		parts = append(parts, "Connected as a VPN")
	default:
		parts = append(parts, "Proxy on "+t.Listen)
	}
	if !t.Since.IsZero() {
		since := t.Since.Local()
		layout := "15:04"
		if since.Format("2006-01-02") != time.Now().Format("2006-01-02") {
			layout = "2006-01-02 15:04"
		}
		parts = append(parts, "since "+since.Format(layout))
	}
	if len(t.Peers) > 0 {
		parts = append(parts, "handshake "+stats.Ago(t.Peers[0].LastHandshake))
	}
	return strings.Join(parts, " \u00B7 ")
}

// showTab shows tab i's controls and hides the others'.
func (w *window) showTab(i int) {
	w.tab = i
	f := w.f
	for j, c := range w.tabs {
		f.setOn(c, j == i)
		f.show(c, w.sel != "")
	}
	formOK := w.sel != "" && w.cfg != nil
	f.show(w.problem, w.sel != "" && w.cfgErr != nil && i != tabText)
	vpn := formOK && i == tabVPN
	for _, c := range []*control{w.hSplit, w.splitOff, w.splitInclude, w.splitExclude, w.modeNote,
		w.appList, w.appAdd, w.appRemove, w.appHint} {
		f.show(c, vpn)
	}
	for _, c := range []*control{w.portLabel, w.port, w.portNote, w.copyAddr, w.proxyHint} {
		f.show(c, formOK && i == tabProxy)
	}
	w.showDetails(formOK && i == tabDetails)
	for _, c := range []*control{w.editor, w.parse, w.revert, w.save} {
		f.show(c, w.sel != "" && i == tabText)
	}
	w.showOverview(w.sel == "")
}

// Input

func (w *window) command(c *control, code uint16) {
	switch c {
	case w.list:
		if code == lbnSelChange {
			w.pick(w.f.listCurSel(w.list))
		}
		return
	case w.appList:
		if code == lbnSelChange {
			w.f.enable(w.appRemove, len(w.f.listSelected(w.appList)) > 0)
		}
		return
	case w.editor:
		if code == enChange && !w.loading && !w.coloring {
			w.checkText()
		}
		return
	case w.port:
		if code == enKillFocus {
			w.applyPort()
		}
		return
	}
	if w.detailsCommand(c, code) || w.overviewCommand(c, code) || code != bnClicked {
		return
	}
	name := w.sel
	switch c {
	case w.add:
		w.addMenu()
	case w.del:
		w.deleteTunnel()
	case w.rename:
		w.renameTunnel()
	case w.segOff:
		go w.a.stop(name)
	case w.segSplit:
		go w.a.run(name, ipc.AsSplit)
	case w.segVPN:
		go w.a.run(name, ipc.AsVPN)
	case w.segProxy:
		go w.a.run(name, ipc.AsProxy)
	case w.reconnect:
		go w.a.apply(name)
	case w.tabs[tabVPN], w.tabs[tabProxy], w.tabs[tabDetails], w.tabs[tabText]:
		for i, t := range w.tabs {
			if t == c && i != w.tab && (w.tab != tabText && w.tab != tabDetails || w.confirmLeave()) {
				w.showTab(i)
			}
		}
	case w.splitOff:
		w.setMode(config.ModeFull)
	case w.splitInclude:
		w.setMode(config.ModeInclude)
	case w.splitExclude:
		w.setMode(config.ModeExclude)
	case w.appAdd:
		w.addApps()
	case w.appRemove:
		w.removeApps()
	case w.copyAddr:
		if w.cfg != nil && w.cfg.Proxy.IsValid() {
			w.copy(w.cfg.Proxy.String())
		}
	case w.revert:
		w.load()
		w.update()
	case w.save:
		w.saveText()
	}
}

func (w *window) enter() {
	if focus, _, _ := procGetFocus.Call(); focus == w.port.hwnd {
		w.applyPort()
	} else if w.tab == tabDetails && w.f.enabled(w.det.save) {
		w.saveDetails()
	}
}

func (w *window) key(c *control, vk uint16) bool {
	switch {
	case c == w.list && vk == vkDelete:
		w.deleteTunnel()
	case c == w.list && vk == vkF2:
		w.renameTunnel()
	case c == w.appList && vk == vkDelete:
		w.removeApps()
	default:
		return false
	}
	return true
}

func (w *window) contextMenu(c *control, x, y int32) {
	if c == w.editor {
		w.editorMenu(x, y)
		return
	}
	if c != w.list {
		return
	}
	i := w.f.listItemAt(c, x, y)
	if i >= 0 && i <= len(w.snap.names) && i != w.rowOf(w.sel) {
		w.f.listSetCurSel(w.list, i)
		w.pick(i)
	}
	if w.sel == "" {
		return
	}
	name := w.sel
	t := w.tunnel()
	file := w.snap.files[name]
	usable := w.snap.link == linkConnected && file.error == ""
	picksApps := file.cfg != nil && file.cfg.Mode != config.ModeFull
	w.f.popup([]menuItem{
		{text: "Connect as the Split VPN", check: t.Running() && t.As == ipc.AsSplit, disabled: !usable || !picksApps, run: func() { go w.a.run(name, ipc.AsSplit) }},
		{text: "Connect as a VPN", check: t.Running() && t.As == ipc.AsVPN, disabled: !usable, run: func() { go w.a.run(name, ipc.AsVPN) }},
		{text: "Connect as a proxy", check: t.Running() && t.As == ipc.AsProxy, disabled: !usable, run: func() { go w.a.run(name, ipc.AsProxy) }},
		{text: "Disconnect", disabled: !t.Running(), run: func() { go w.a.stop(name) }},
		{},
		{text: "Rename...\tF2", run: w.renameTunnel},
		{text: "Delete...\tDel", run: w.deleteTunnel},
	}, x, y)
}

// editorMenu offers the editing commands of the text at the screen point.
func (w *window) editorMenu(x, y int32) {
	h := w.editor.hwnd
	var sel charRange
	procSendMessageW.Call(h, emExGetSel, 0, uintptr(unsafe.Pointer(&sel)))
	none := sel.min == sel.max
	canUndo, _, _ := procSendMessageW.Call(h, emCanUndo, 0, 0)
	send := func(msg uintptr) func() { return func() { procSendMessageW.Call(h, msg, 0, 0) } }
	w.f.popup([]menuItem{
		{text: "Undo\tCtrl+Z", disabled: canUndo == 0, run: send(wmUndo)},
		{},
		{text: "Cut\tCtrl+X", disabled: none, run: send(wmCut)},
		{text: "Copy\tCtrl+C", disabled: none, run: send(wmCopy)},
		{text: "Paste\tCtrl+V", run: func() { pastePlain(h) }},
		{text: "Delete\tDel", disabled: none, run: send(wmClear)},
		{},
		{text: "Select all\tCtrl+A", run: func() {
			all := charRange{0, -1}
			procSendMessageW.Call(h, emExSetSel, 0, uintptr(unsafe.Pointer(&all)))
		}},
	}, x, y)
}

// pick selects row i of the tunnel list, the Overview or a tunnel, unless
// unsaved text keeps the current tunnel.
func (w *window) pick(i int) {
	if i < 0 || i > len(w.snap.names) || i == w.rowOf(w.sel) {
		return
	}
	if !w.confirmLeave() {
		w.f.listSetCurSel(w.list, w.rowOf(w.sel))
		return
	}
	w.sel = w.nameAt(i)
	w.f.listSetCurSel(w.list, i)
	w.load()
	w.update()
}

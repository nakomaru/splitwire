package tray

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"splitwire/internal/apps"
	"splitwire/internal/config"
)

// pickRow is a program the picker offers.
type pickRow struct {
	path, name, tag string
	// entry is the App setting the row adds.
	entry string
}

// picker is the dialog that adds apps to a tunnel.
type picker struct {
	f     *form
	icons iconCache
	rows  []pickRow
	// shown lists the rows the search matches, as indexes into rows, with
	// a typed path first when the search is one.
	shown   []int
	typed   *pickRow
	checked map[string]bool
	done    bool
	result  []string

	intro, search, list, browse, ok, cancel *control
}

// pickApps asks which apps to add to the tunnel, offering the running,
// recently used and Start menu programs it lacks. It returns their App
// settings, or nothing when canceled.
func pickApps(owner uintptr, tunnel string, have []string) []string {
	p := newPicker(owner, tunnel, have)
	procEnableWindow.Call(owner, 0)
	procShowWindow.Call(p.f.hwnd, swShowNormal)
	procSetFocus.Call(p.search.hwnd)
	runForms(func() bool { return p.done })
	procEnableWindow.Call(owner, 1)
	procSetForegroundWindow.Call(owner)
	procDestroyWindow.Call(p.f.hwnd)
	p.icons.free()
	return p.result
}

// newPicker creates the picker's hidden window.
func newPicker(owner uintptr, tunnel string, have []string) *picker {
	known := make(map[string]bool)
	for _, h := range have {
		known[strings.ToLower(h)] = true
		if paths, err := config.ExpandApp(h); err == nil {
			for _, p := range paths {
				known[strings.ToLower(p)] = true
			}
		}
	}
	p := &picker{icons: iconCache{}, checked: make(map[string]bool)}
	for _, c := range apps.Find() {
		entry := apps.Pattern(c.Path)
		if known[strings.ToLower(c.Path)] || known[strings.ToLower(entry)] {
			continue
		}
		tag := "Start menu"
		switch {
		case c.Window:
			tag = "Running"
		case !c.LastUsed.IsZero():
			tag = "Used " + c.LastUsed.Local().Format("2006-01-02")
		case !c.StartMenu:
			tag = "In the background"
		}
		p.rows = append(p.rows, pickRow{path: c.Path, name: c.Name, tag: tag, entry: entry})
	}

	f := &form{minW: 480, minH: 420}
	p.f = f
	f.layout = p.layout
	f.command = p.command
	f.enter = func() {
		if len(p.checked) > 0 {
			p.accept()
		}
	}
	f.escape = func() { p.done = true }
	f.close = func() { p.done = true }
	const style = wsCaption | wsSysMenu | wsThickFrame
	newForm(f, "Add apps to "+tunnel, owner, style, 620, 660)
	p.intro = f.add(&control{kind: kindLabel, wrap: true,
		text: "Pick the programs for " + tunnel + ". Programs they start follow them, so a launcher covers its games."})
	p.search = f.addEdit(&control{}, 0)
	cue, _ := windows.UTF16PtrFromString("Search, or type a path such as C:\\Games\\*\\game.exe")
	procSendMessageW.Call(p.search.hwnd, emSetCueBanner, 1, uintptr(unsafe.Pointer(cue)))
	const lbsMultipleSel = 0x0008
	p.list = f.addList(&control{itemHeight: 46, checks: true, empty: "No programs match."}, lbsMultipleSel)
	p.list.drawItem = p.drawRow
	p.browse = f.add(&control{kind: kindButton, text: "Browse..."})
	p.ok = f.add(&control{kind: kindButton, text: "Add", primary: true})
	p.cancel = f.add(&control{kind: kindButton, text: "Cancel"})
	f.ready = true
	p.filter()
	p.relayout()
	return p
}

func (p *picker) relayout() {
	var r rect
	procGetClientRect.Call(p.f.hwnd, uintptr(unsafe.Pointer(&r)))
	p.layout(r.right, r.bottom)
}

func (p *picker) layout(cw, ch int32) {
	f := p.f
	s := f.px
	m := s(20)
	bh := s(32)
	y := m
	ih := f.measureWrapped(p.intro.text, f.fonts[fontNormal], cw-2*m)
	f.place(p.intro, rect{m, y, cw - m, y + ih})
	y += ih + s(12)
	f.place(p.search, rect{m, y, cw - m, y + bh})
	y += bh + s(12)
	by := ch - m - bh
	f.place(p.list, rect{m, y, cw - m, by - s(16)})
	bw := f.buttonWidth(p.browse)
	f.place(p.browse, rect{m, by, m + bw, by + bh})
	cw2 := f.buttonWidth(p.cancel)
	f.place(p.cancel, rect{cw - m - cw2, by, cw - m, by + bh})
	ow := clamp(f.buttonWidth(p.ok), s(110), s(200))
	f.place(p.ok, rect{cw - m - cw2 - s(8) - ow, by, cw - m - cw2 - s(8), by + bh})
}

// isPattern reports whether the search text is a path to add as typed.
func isPattern(s string) bool {
	return strings.HasPrefix(s, "%") || filepath.IsAbs(s) && strings.Contains(s, `\`)
}

// filter shows the rows that match the search, keeping their checks.
func (p *picker) filter() {
	q := strings.TrimSpace(windowText(p.search.hwnd))
	p.typed = nil
	if isPattern(q) {
		p.typed = &pickRow{path: q, name: "Typed path", tag: "Typed", entry: q}
		if !strings.ContainsAny(q, "*?[%") {
			p.typed.name = apps.DisplayName(q)
		}
	}
	lq := strings.ToLower(q)
	p.shown = p.shown[:0]
	for i, r := range p.rows {
		lp := strings.ToLower(r.path)
		match := true
		switch {
		case p.typed != nil:
			match = strings.HasPrefix(lp, strings.TrimRight(lq, "*?"))
		case lq != "":
			match = strings.Contains(strings.ToLower(r.name), lq) || strings.Contains(lp, lq)
		}
		if match {
			p.shown = append(p.shown, i)
		}
	}
	items := make([]string, 0, len(p.shown)+1)
	if p.typed != nil {
		items = append(items, p.typed.entry)
	}
	for _, i := range p.shown {
		items = append(items, p.rows[i].entry)
	}
	p.f.listSet(p.list, items)
	for i := range items {
		if p.checked[strings.ToLower(p.row(i).entry)] {
			p.f.listSetSel(p.list, i, true)
		}
	}
	p.updateOK()
}

// row is the picker row at list index i.
func (p *picker) row(i int) *pickRow {
	if p.typed != nil {
		if i == 0 {
			return p.typed
		}
		i--
	}
	return &p.rows[p.shown[i]]
}

func (p *picker) updateOK() {
	n := len(p.checked)
	text := "Add"
	if n > 1 {
		text = fmt.Sprintf("Add %d apps", n)
	} else if n == 1 {
		text = "Add 1 app"
	}
	p.f.setText(p.ok, text)
	p.f.enable(p.ok, n > 0)
}

func (p *picker) command(c *control, code uint16) {
	switch c {
	case p.search:
		if code == enChange {
			p.filter()
		}
		return
	case p.list:
		if code == lbnSelChange {
			selected := make(map[int]bool)
			for _, i := range p.f.listSelected(p.list) {
				selected[i] = true
			}
			for i := 0; i < p.f.listCount(p.list); i++ {
				k := strings.ToLower(p.row(i).entry)
				if selected[i] {
					p.checked[k] = true
				} else {
					delete(p.checked, k)
				}
			}
			p.updateOK()
		}
		return
	}
	if code != bnClicked {
		return
	}
	switch c {
	case p.browse:
		path, ok := openFile(p.f.hwnd, "Choose a program", "Programs (*.exe)", "*.exe", "All files", "*.*")
		if !ok {
			return
		}
		entry := apps.Pattern(path)
		p.rows = append([]pickRow{{path: path, name: apps.DisplayName(path), tag: "Chosen", entry: entry}}, p.rows...)
		p.checked[strings.ToLower(entry)] = true
		p.f.setText(p.search, "")
		p.filter()
	case p.ok:
		p.accept()
	case p.cancel:
		p.done = true
	}
}

// accept returns the checked rows' App settings in the order shown.
func (p *picker) accept() {
	seen := make(map[string]bool)
	add := func(r *pickRow) {
		k := strings.ToLower(r.entry)
		if p.checked[k] && !seen[k] {
			seen[k] = true
			p.result = append(p.result, r.entry)
		}
	}
	if p.typed != nil {
		add(p.typed)
	}
	for i := range p.rows {
		add(&p.rows[i])
	}
	p.done = true
}

func (p *picker) drawRow(dc uintptr, i int, r rect, selected bool) {
	if i >= p.f.listCount(p.list) {
		return
	}
	f := p.f
	row := p.row(i)
	box := rect{r.left + f.px(10), r.top, r.left + f.px(30), r.bottom}
	if selected {
		f.drawGlyph(dc, glyphCheckboxFill, 20, box, f.col.accent)
		f.drawGlyph(dc, glyphCheckMark, 14, box, f.col.onAccnt)
	} else {
		f.drawGlyph(dc, glyphCheckbox, 20, box, f.col.subtext)
	}
	size := f.px(24)
	icon := row.path
	if strings.ContainsAny(icon, "*?[%") {
		icon = ""
	}
	drawIcon(dc, p.icons.get(icon, size), r.left+f.px(40), r.top+(r.bottom-r.top-size)/2, size)
	x := r.left + f.px(76)
	tw, _ := f.measure(row.tag, f.fonts[fontNormal])
	drawText(dc, row.tag, rect{r.right - f.px(12) - tw, r.top, r.right - f.px(12), r.bottom}, f.fonts[fontNormal], f.col.subtext, dtSingleLine|dtVCenter)
	right := r.right - f.px(28) - tw
	drawText(dc, row.name, rect{x, r.top + f.px(5), right, r.top + f.px(24)}, f.fonts[fontNormal], f.col.text, dtSingleLine|dtVCenter|dtEndEllipsis)
	drawText(dc, row.entry, rect{x, r.top + f.px(23), right, r.bottom - f.px(4)}, f.fonts[fontNormal], f.col.subtext, dtSingleLine|dtVCenter|dtPathEllipsis)
}

package tray

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"splitwire/internal/config"
	"splitwire/internal/ipc"
	"splitwire/internal/userconf"
	"splitwire/internal/warp"
)

const (
	idYes = 6
	idNo  = 7
)

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func (w *window) copy(s string) {
	if err := copyText(s); err != nil {
		messageBox(w.f.hwnd, "Could not copy:\n\n"+err.Error(), windows.MB_ICONERROR)
	}
}

// confirmLeave asks what to do with unsaved text, and reports whether the
// window may move on.
func (w *window) confirmLeave() bool {
	if !w.dirty {
		return true
	}
	switch messageBox(w.f.hwnd, "Save the changes to "+w.sel+"?", windows.MB_YESNOCANCEL|windows.MB_ICONWARNING) {
	case idYes:
		return w.saveText()
	case idNo:
		w.load()
		w.update()
		return true
	}
	return false
}

// edit applies a change to the selected tunnel's file and shows the result.
func (w *window) edit(change func(string) string) {
	if w.path == "" {
		return
	}
	if err := userconf.Update(w.path, change); err != nil {
		messageBox(w.f.hwnd, "Could not save "+w.sel+":\n\n"+err.Error(), windows.MB_ICONERROR)
	}
	w.load()
	w.update()
}

func (w *window) setValue(key, val string, isDefault bool) {
	w.edit(func(text string) string { return config.SetValue(text, key, val, isDefault) })
}

// setMode picks the apps the tunnel covers. A split mode without apps asks
// for apps first.
func (w *window) setMode(m config.Mode) {
	if w.cfg == nil || w.cfg.Mode == m {
		return
	}
	list := w.cfg.Apps
	if m != config.ModeFull && len(list) == 0 {
		added := w.pickApps()
		if len(added) == 0 {
			// The radio buttons go back to the file's mode.
			w.update()
			return
		}
		list = added
	}
	w.edit(func(text string) string {
		return config.SetApps(config.SetValue(text, "Mode", m.String(), m == config.ModeFull && len(list) == 0), list)
	})
}

// pickApps asks for apps that the tunnel lacks.
func (w *window) pickApps() []string {
	var have []string
	if w.cfg != nil {
		have = w.cfg.Apps
	}
	return pickApps(w.f.hwnd, w.sel, have)
}

func (w *window) addApps() {
	if w.cfg == nil {
		return
	}
	added := w.pickApps()
	if len(added) == 0 {
		return
	}
	all := append(append([]string(nil), w.cfg.Apps...), added...)
	w.edit(func(text string) string { return config.SetApps(text, all) })
}

func (w *window) removeApps() {
	sel := w.f.listSelected(w.appList)
	if w.cfg == nil || len(sel) == 0 {
		return
	}
	drop := make(map[int]bool)
	for _, i := range sel {
		drop[i] = true
	}
	var kept []string
	for i, a := range w.cfg.Apps {
		if !drop[i] {
			kept = append(kept, a)
		}
	}
	if len(kept) == 0 && w.cfg.Mode != config.ModeFull {
		messageBox(w.f.hwnd, "This choice needs at least one app. To remove them all, pick \"All apps\" first.", windows.MB_ICONINFORMATION)
		return
	}
	w.edit(func(text string) string { return config.SetApps(text, kept) })
}

func (w *window) applyPort() {
	if w.cfg == nil {
		return
	}
	text := strings.TrimSpace(windowText(w.port.hwnd))
	if text == "" {
		return
	}
	port, err := strconv.ParseUint(text, 10, 16)
	switch {
	case err != nil || port == 0:
		err = errors.New("enter a port from 1 to 65535")
	case w.cfg.Proxy.IsValid() && uint16(port) == w.cfg.Proxy.Port():
		return
	default:
		t := w.tunnel()
		err = userconf.SetProxyPort(w.path, uint16(port), t.Running() && t.As == ipc.AsProxy)
	}
	if err != nil {
		messageBox(w.f.hwnd, "Could not use that port:\n\n"+err.Error(), windows.MB_ICONWARNING)
		procSetFocus.Call(w.port.hwnd)
		procSendMessageW.Call(w.port.hwnd, emSetSel, 0, ^uintptr(0))
		return
	}
	w.load()
	w.update()
}

// checkText parses the editor's text and shows the result.
func (w *window) checkText() {
	text := normalize(windowText(w.editor.hwnd))
	w.dirty = w.sel != "" && text != w.text
	_, err := config.Parse(text, w.sel)
	f := w.f
	switch {
	case w.sel == "":
		f.setText(w.parse, "")
	case err != nil:
		w.parse.color = labelError
		msg := err.Error()
		if line := errorLine(text, err); line > 0 {
			msg = fmt.Sprintf("Line %d: %s", line, msg)
		}
		f.setText(w.parse, msg)
	case w.dirty:
		w.parse.color = labelSuccess
		f.setText(w.parse, "No problems found. Save to keep the changes.")
	default:
		w.parse.color = labelSubtle
		f.setText(w.parse, "No problems found.")
	}
	f.invalidate(w.parse)
	f.enable(w.save, w.dirty && err == nil)
	f.enable(w.revert, w.dirty)
}

// offender matches the quoted text that WireGuard's parse errors end with.
var offender = regexp.MustCompile(`: ("(?:[^"\\]|\\.)*")$`)

// errorLine finds the line of a WireGuard parse error by the text it
// quotes, or 0.
func errorLine(text string, err error) int {
	m := offender.FindStringSubmatch(err.Error())
	if m == nil {
		return 0
	}
	what, uerr := strconv.Unquote(m[1])
	if uerr != nil || what == "" {
		return 0
	}
	for i, line := range strings.Split(text, "\n") {
		if strings.Contains(line, what) {
			return i + 1
		}
	}
	return 0
}

// saveText writes the editor's text to the file, and reports success.
func (w *window) saveText() bool {
	text := normalize(windowText(w.editor.hwnd))
	if _, err := config.Parse(text, w.sel); err != nil {
		messageBox(w.f.hwnd, "Fix the problem before saving:\n\n"+err.Error(), windows.MB_ICONWARNING)
		return false
	}
	out := text
	if w.crlf {
		out = strings.ReplaceAll(text, "\n", "\r\n")
	}
	if err := os.WriteFile(w.path, []byte(out), 0o600); err != nil {
		messageBox(w.f.hwnd, "Could not save "+w.sel+":\n\n"+err.Error(), windows.MB_ICONERROR)
		return false
	}
	w.load()
	w.update()
	return true
}

func (w *window) addMenu() {
	f := w.f
	f.popupUnder(w.add, []menuItem{
		{text: "New empty tunnel", run: func() {
			name, err := userconf.NewEmpty()
			if err != nil {
				messageBox(f.hwnd, "Could not create a tunnel:\n\n"+err.Error(), windows.MB_ICONERROR)
				return
			}
			w.selectNew(name, tabText)
		}},
		{text: "Import from file...", run: func() {
			path, ok := openFile(f.hwnd, "Import a tunnel", "WireGuard configurations (*.conf)", "*.conf", "All files", "*.*")
			if !ok {
				return
			}
			name, err := userconf.Import(path)
			if err != nil {
				messageBox(f.hwnd, "Could not import "+path+":\n\n"+err.Error(), windows.MB_ICONERROR)
				return
			}
			w.selectNew(name, tabApps)
		}},
		{text: "Import from the WireGuard app...", run: func() { go w.a.importTunnels() }},
		{text: "Create a WARP tunnel...", run: w.createWARP},
		{},
		{text: "Open the configuration folder", run: w.a.openFolder},
	})
}

// selectNew selects a tunnel that was just written, on the tab.
func (w *window) selectNew(name string, tab int) {
	if w.a.scanTunnels() {
		go w.a.rebuild()
	}
	w.a.mu.Lock()
	w.a.winSelect = name
	w.a.mu.Unlock()
	w.refresh()
	if w.sel == name {
		w.showTab(tab)
		if tab == tabText {
			procSetFocus.Call(w.editor.hwnd)
		}
	}
}

func (w *window) createWARP() {
	if _, ok := askOptionsOwned(w.f.hwnd, "Create a WARP tunnel",
		"Registers a free device with Cloudflare WARP and saves it as a tunnel. It uses the "+
			"registration of Cloudflare's own app, which is unofficial and could change.",
		nil, "Create"); !ok {
		return
	}
	go func() {
		if name := w.a.createWARP(); name != "" {
			w.a.showInWindow(name)
		}
	}()
}

func (w *window) renameTunnel() {
	name := w.sel
	if name == "" {
		return
	}
	if w.tunnel().Running() {
		messageBox(w.f.hwnd, "Disconnect "+name+" before renaming it.", windows.MB_ICONINFORMATION)
		return
	}
	if !w.confirmLeave() {
		return
	}
	newName, ok := askText(w.f.hwnd, "Rename "+name, "New name for the tunnel "+name+":", name, func(s string) error {
		if s == name {
			return nil
		}
		if err := userconf.ValidName(s); err != nil {
			return err
		}
		for _, n := range w.snap.names {
			if strings.EqualFold(n, s) && !strings.EqualFold(n, name) {
				return fmt.Errorf("a tunnel named %s exists", n)
			}
		}
		return nil
	})
	if !ok || newName == name {
		return
	}
	if err := userconf.Rename(name, newName); err != nil {
		messageBox(w.f.hwnd, "Could not rename "+name+":\n\n"+err.Error(), windows.MB_ICONERROR)
		return
	}
	w.selectNew(newName, w.tab)
}

func (w *window) deleteTunnel() {
	name := w.sel
	if name == "" {
		return
	}
	running := w.tunnel().Running()
	q := "Move the tunnel " + name + " to the Recycle Bin?"
	if running {
		q = name + " is connected. Disconnect it and move it to the Recycle Bin?"
	}
	if messageBox(w.f.hwnd, q, windows.MB_YESNO|windows.MB_ICONWARNING|windows.MB_DEFBUTTON2) != idYes {
		return
	}
	w.dirty = false
	go func() {
		if running {
			w.a.stop(name)
		}
		if err := userconf.Recycle(name); err != nil {
			errorBox("Could not delete %s:\n\n%v", name, err)
		}
	}()
}

// createWARP registers a Cloudflare WARP device and saves it as a tunnel,
// returning its name, or "" after showing the failure.
func (a *app) createWARP() string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := warp.Register(ctx)
	if err != nil {
		errorBox("Could not create a WARP tunnel:\n\n%v", err)
		return ""
	}
	name, err := userconf.CreateNew("WARP", d.Config())
	if err != nil {
		warp.Delete(ctx, d.ID, d.Token)
		errorBox("Could not save the WARP tunnel:\n\n%v", err)
		return ""
	}
	return name
}

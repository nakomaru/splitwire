package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"splitwire/internal/bootstrap"
	"splitwire/internal/config"
	"splitwire/internal/elevate"
	"splitwire/internal/ipc"
	"splitwire/internal/stats"
	"splitwire/internal/svcwait"
	"splitwire/internal/userconf"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// Connection states between the tray and the manager.
const (
	linkConnecting = iota
	linkConnected
	linkMissing // manager service not installed
	linkFailed
)

type app struct {
	icons map[string][]byte

	mu       sync.Mutex
	status   ipc.Status
	link     int
	linkErr  string
	tunnels  []string
	hashes   map[string]string // expanded configuration hash per tunnel
	retry    chan struct{}
	gen      chan struct{}
	items    map[string]*systray.MenuItem
	statusMI *systray.MenuItem
	statsMI  *systray.MenuItem
	applyMI  *systray.MenuItem
	bootMI   *systray.MenuItem
	loginMI  *systray.MenuItem
	setupMI  *systray.MenuItem
}

func newApp() *app {
	return &app{
		icons: map[string][]byte{
			"down":  icoBytes(colorDown),
			"busy":  icoBytes(colorBusy),
			"up":    icoBytes(colorUp),
			"error": icoBytes(colorError),
		},
		status: ipc.Status{State: ipc.StateDown},
		hashes: make(map[string]string),
		retry:  make(chan struct{}, 1),
		items:  make(map[string]*systray.MenuItem),
	}
}

func (a *app) ready() {
	systray.SetIcon(a.icons["down"])
	systray.SetTooltip("splitwire")
	a.scanTunnels()
	a.rebuild()
	go a.watchFolder()
	go a.watchManager()
}

// ---- menu ----

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

	a.statusMI = systray.AddMenuItem("splitwire", "")
	a.statusMI.Disable()
	a.statsMI = systray.AddMenuItem("", "")
	a.statsMI.Disable()
	a.statsMI.Hide()
	systray.AddSeparator()

	a.items = make(map[string]*systray.MenuItem)
	if len(a.tunnels) == 0 {
		none := systray.AddMenuItem("No tunnels yet: import or add a .conf", "")
		none.Disable()
	}
	for _, name := range a.tunnels {
		name := name
		item := systray.AddMenuItemCheckbox(name, "Connect or disconnect "+name, false)
		a.items[name] = item
		a.onClick(item, gen, func() { a.toggle(name) })
	}
	a.applyMI = systray.AddMenuItem("Apply configuration changes", "Reconnect with the edited configuration")
	a.applyMI.Hide()
	a.onClick(a.applyMI, gen, a.apply)
	systray.AddSeparator()

	edit := systray.AddMenuItem("Edit configuration", "")
	if len(a.tunnels) == 0 {
		edit.Disable()
	}
	for _, name := range a.tunnels {
		name := name
		a.onClick(edit.AddSubMenuItem(name, ""), gen, func() { a.edit(name) })
	}
	a.onClick(systray.AddMenuItem("Open configuration folder", ""), gen, a.openFolder)
	a.onClick(systray.AddMenuItem("Import from WireGuard app...", "Copy tunnels from the WireGuard app (asks for administrator rights)"), gen, a.importTunnels)
	a.onClick(systray.AddMenuItem("Show manager log", ""), gen, a.showLog)
	systray.AddSeparator()

	a.bootMI = systray.AddMenuItemCheckbox("Connect at boot", "Bring this tunnel up when Windows starts", false)
	a.onClick(a.bootMI, gen, a.toggleBoot)
	a.loginMI = systray.AddMenuItemCheckbox("Start splitwire at sign-in", "", runAtLogin())
	a.onClick(a.loginMI, gen, a.toggleLogin)
	a.setupMI = systray.AddMenuItem("Set up splitwire (administrator)...", "Install the splitwire manager service")
	a.setupMI.Hide()
	a.onClick(a.setupMI, gen, a.setup)
	systray.AddSeparator()
	a.onClick(systray.AddMenuItem("Quit", "Close the tray app; a running tunnel stays up"), gen, systray.Quit)

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

// refreshLocked updates icon, tooltip and item states from the current state.
func (a *app) refreshLocked() {
	if a.statusMI == nil {
		return
	}
	st := a.status
	icon, title, tip := "down", "", "splitwire"
	switch a.link {
	case linkConnecting:
		title = "Connecting to the splitwire manager..."
	case linkMissing:
		title = "The splitwire manager is not set up"
	case linkFailed:
		icon, title = "error", "Manager unavailable: "+truncate(a.linkErr, 60)
	case linkConnected:
		switch st.State {
		case ipc.StateDown:
			title = "Not connected"
		case ipc.StateStarting:
			icon, title = "busy", "Connecting "+st.Tunnel+"..."
		case ipc.StateStopping:
			icon, title = "busy", "Disconnecting "+st.Tunnel+"..."
		case ipc.StateUp:
			icon = "up"
			title = st.Tunnel + " connected (" + st.Mode
			switch {
			case st.Mode != "full" && st.Apps == 1:
				title += ", 1 app"
			case st.Mode != "full":
				title += fmt.Sprintf(", %d apps", st.Apps)
			}
			title += ")"
		case ipc.StateError:
			icon, title = "error", st.Tunnel+" failed: "+truncate(st.Error, 60)
		}
	}
	tip = "splitwire: " + title
	systray.SetIcon(a.icons[icon])
	systray.SetTooltip(truncate(tip, 120))
	a.statusMI.SetTitle(title)

	if a.link == linkConnected && st.State == ipc.StateUp && len(st.Peers) > 0 {
		p := st.Peers[0]
		a.statsMI.SetTitle(fmt.Sprintf("Handshake %s, received %s, sent %s",
			stats.Ago(p.LastHandshake), stats.Bytes(p.RxBytes), stats.Bytes(p.TxBytes)))
		a.statsMI.Show()
	} else {
		a.statsMI.Hide()
	}

	active := a.link == linkConnected && (st.State == ipc.StateUp || st.State == ipc.StateStarting)
	for name, item := range a.items {
		if active && name == st.Tunnel {
			item.Check()
		} else {
			item.Uncheck()
		}
		if a.link == linkConnected {
			item.Enable()
		} else {
			item.Disable()
		}
	}

	if st.State == ipc.StateUp && a.hashes[st.Tunnel] != "" && a.hashes[st.Tunnel] != st.ConfigHash {
		a.applyMI.SetTitle("Apply changes to " + st.Tunnel)
		a.applyMI.Show()
	} else {
		a.applyMI.Hide()
	}

	switch {
	case a.link != linkConnected:
		a.bootMI.SetTitle("Connect at boot")
		a.bootMI.Uncheck()
		a.bootMI.Disable()
	case st.Autostart != "":
		a.bootMI.SetTitle("Connect " + st.Autostart + " at boot")
		a.bootMI.Check()
		a.bootMI.Enable()
	case st.State == ipc.StateUp:
		a.bootMI.SetTitle("Connect " + st.Tunnel + " at boot")
		a.bootMI.Uncheck()
		a.bootMI.Enable()
	default:
		a.bootMI.SetTitle("Connect at boot")
		a.bootMI.Uncheck()
		a.bootMI.Disable()
	}

	if a.link == linkMissing || a.link == linkFailed {
		a.setupMI.Show()
	} else {
		a.setupMI.Hide()
	}
}

// ---- manager connection ----

func (a *app) setLink(link int, err string) {
	a.mu.Lock()
	a.link, a.linkErr = link, err
	a.refreshLocked()
	a.mu.Unlock()
}

func (a *app) setStatus(st ipc.Status) {
	a.mu.Lock()
	a.status = st
	a.refreshLocked()
	a.mu.Unlock()
}

// watchManager keeps a watch stream open to the manager, reconnecting when
// the service restarts.
func (a *app) watchManager() {
	var pid uint32
	for {
		if !svcwait.Exists(ipc.ServiceName) {
			a.setLink(linkMissing, "")
		} else {
			a.setLink(linkConnecting, "")
		}
		var err error
		pid, err = svcwait.RunningOtherThan(ipc.ServiceName, pid)
		if err != nil {
			a.setLink(linkFailed, err.Error())
			<-a.retry
			pid = 0
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := ipc.Dial(ctx)
		cancel()
		if err != nil {
			msg := err.Error()
			if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				msg = "access denied; the manager was set up by another user"
			}
			a.setLink(linkFailed, msg)
			<-a.retry
			pid = 0
			continue
		}
		if err := conn.Send(ipc.Request{Op: ipc.OpWatch}); err != nil {
			conn.Close()
			continue
		}
		a.setLink(linkConnected, "")
		for {
			var st ipc.Status
			if err := conn.Receive(&st); err != nil {
				break
			}
			a.setStatus(st)
		}
		conn.Close()
	}
}

func call(req ipc.Request) (*ipc.Reply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := ipc.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Call(req)
}

// ---- tunnel files ----

func expandedConfig(name string) (string, error) {
	path, err := userconf.Resolve(name)
	if err != nil {
		return "", err
	}
	c, err := config.Load(path)
	if err != nil {
		return "", err
	}
	return c.WithExpandedApps()
}

func (a *app) scanTunnels() bool {
	names, _ := userconf.Names()
	hashes := make(map[string]string, len(names))
	for _, n := range names {
		if text, err := expandedConfig(n); err == nil {
			hashes[n] = ipc.ConfigHash(text)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := strings.Join(names, "\x00") != strings.Join(a.tunnels, "\x00")
	a.tunnels, a.hashes = names, hashes
	return changed
}

// watchFolder rescans tunnels whenever the configuration folder changes.
func (a *app) watchFolder() {
	dir, err := userconf.EnsureDir()
	if err != nil {
		return
	}
	h, err := windows.FindFirstChangeNotification(dir, false,
		windows.FILE_NOTIFY_CHANGE_FILE_NAME|windows.FILE_NOTIFY_CHANGE_LAST_WRITE)
	if err != nil {
		return
	}
	defer windows.FindCloseChangeNotification(h)
	for {
		if _, err := windows.WaitForSingleObject(h, windows.INFINITE); err != nil {
			return
		}
		if a.scanTunnels() {
			a.rebuild()
		} else {
			a.refresh()
		}
		if err := windows.FindNextChangeNotification(h); err != nil {
			return
		}
	}
}

// ---- actions ----

func errorBox(format string, args ...any) {
	text, _ := windows.UTF16PtrFromString(fmt.Sprintf(format, args...))
	caption, _ := windows.UTF16PtrFromString("splitwire")
	windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
}

func (a *app) toggle(name string) {
	a.mu.Lock()
	st := a.status
	a.mu.Unlock()
	if st.Tunnel == name && (st.State == ipc.StateUp || st.State == ipc.StateStarting) {
		if _, err := call(ipc.Request{Op: ipc.OpDown}); err != nil {
			errorBox("Could not disconnect %s:\n\n%v", name, err)
		}
		return
	}
	a.connect(name)
}

func (a *app) connect(name string) {
	text, err := expandedConfig(name)
	if err != nil {
		errorBox("%s has a problem:\n\n%v", name, err)
		return
	}
	if _, err := call(ipc.Request{Op: ipc.OpUp, Name: name, Config: text}); err != nil {
		errorBox("Could not connect %s:\n\n%v", name, err)
	}
}

func (a *app) apply() {
	a.mu.Lock()
	name := a.status.Tunnel
	a.mu.Unlock()
	if name != "" {
		a.connect(name)
	}
}

func (a *app) toggleBoot() {
	a.mu.Lock()
	st := a.status
	a.mu.Unlock()
	req := ipc.Request{Op: ipc.OpAutostart}
	if st.Autostart == "" {
		if st.State != ipc.StateUp {
			return
		}
		text, err := expandedConfig(st.Tunnel)
		if err != nil {
			errorBox("%s has a problem:\n\n%v", st.Tunnel, err)
			return
		}
		req.Name, req.Config = st.Tunnel, text
	}
	if _, err := call(req); err != nil {
		errorBox("Could not change the boot tunnel:\n\n%v", err)
	}
}

func (a *app) edit(name string) {
	path, err := userconf.Resolve(name)
	if err != nil {
		errorBox("%v", err)
		return
	}
	exec.Command("notepad.exe", path).Start()
}

func (a *app) openFolder() {
	dir, err := userconf.EnsureDir()
	if err != nil {
		errorBox("%v", err)
		return
	}
	exec.Command("explorer.exe", dir).Start()
}

func (a *app) showLog() {
	rep, err := call(ipc.Request{Op: ipc.OpLog})
	if err != nil {
		errorBox("Could not read the manager log:\n\n%v", err)
		return
	}
	path := filepath.Join(os.TempDir(), "splitwire-manager.log")
	if err := os.WriteFile(path, []byte(strings.Join(rep.Log, "\r\n")+"\r\n"), 0o600); err != nil {
		errorBox("%v", err)
		return
	}
	exec.Command("notepad.exe", path).Start()
}

// cliExe finds splitwire.exe beside the tray app, or the installed copy.
func cliExe() string {
	if self, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(self), "splitwire.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	bin, _ := bootstrap.BinDir()
	return filepath.Join(bin, "splitwire.exe")
}

// runElevated runs a CLI command elevated in a console window that stays
// open on failure, so its error is readable there.
func runElevated(args ...string) {
	if _, err := elevate.RunWait(cliExe(), append([]string{elevate.HoldOnErrorFlag}, args...), true); err != nil {
		errorBox("%v", err)
	}
}

func (a *app) importTunnels() { runElevated("import") }

func (a *app) setup() {
	runElevated("manager", "install")
	select {
	case a.retry <- struct{}{}:
	default:
	}
}

// ---- start at sign-in ----

func trayPath() string {
	bin, err := bootstrap.BinDir()
	if err == nil {
		p := filepath.Join(bin, bootstrap.TrayExe)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	self, _ := os.Executable()
	return self
}

func runAtLogin() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue("splitwire")
	return err == nil
}

func (a *app) toggleLogin() {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		errorBox("%v", err)
		return
	}
	defer k.Close()
	if runAtLogin() {
		err = k.DeleteValue("splitwire")
	} else {
		err = k.SetStringValue("splitwire", windows.EscapeArg(trayPath()))
	}
	if err != nil {
		errorBox("%v", err)
	}
	a.mu.Lock()
	if runAtLogin() {
		a.loginMI.Check()
	} else {
		a.loginMI.Uncheck()
	}
	a.mu.Unlock()
}

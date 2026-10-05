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

// tunnelFile is what the tray knows about a configuration file.
type tunnelFile struct {
	hash  string // hash of the expanded configuration text
	cfg   *config.Config
	error string
}

// tunnelMenu is a tunnel's entry and its submenu.
type tunnelMenu struct {
	item, vpn, proxy, off *systray.MenuItem
	stats, problem, apply *systray.MenuItem
}

type app struct {
	icons map[string][]byte

	mu      sync.Mutex
	status  ipc.Status
	link    int
	linkErr string
	names   []string
	files   map[string]tunnelFile
	retry   chan struct{}
	gen     chan struct{}

	menus     map[string]*tunnelMenu
	summaryMI *systray.MenuItem
	downAllMI *systray.MenuItem
	bootMI    *systray.MenuItem
	loginMI   *systray.MenuItem
	setupMI   *systray.MenuItem
}

func newApp() *app {
	return &app{
		icons: map[string][]byte{
			"down":  icoBytes(colorDown),
			"busy":  icoBytes(colorBusy),
			"up":    icoBytes(colorUp),
			"error": icoBytes(colorError),
		},
		files: make(map[string]tunnelFile),
		retry: make(chan struct{}, 1),
		menus: make(map[string]*tunnelMenu),
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

	a.summaryMI = systray.AddMenuItem("splitwire", "")
	a.summaryMI.Disable()
	systray.AddSeparator()

	a.menus = make(map[string]*tunnelMenu)
	if len(a.names) == 0 {
		none := systray.AddMenuItem("No tunnels yet: import or add a .conf", "")
		none.Disable()
	}
	for _, name := range a.names {
		name := name
		m := &tunnelMenu{item: systray.AddMenuItemCheckbox(name, "", false)}
		m.vpn = m.item.AddSubMenuItemCheckbox("VPN", "Route apps by this tunnel's Mode; one tunnel runs as the VPN at a time", false)
		m.proxy = m.item.AddSubMenuItemCheckbox("Proxy", "Serve this tunnel as a local SOCKS5 and HTTP proxy; any number run at once", false)
		m.off = m.item.AddSubMenuItemCheckbox("Off", "", true)
		m.stats = m.item.AddSubMenuItem("", "")
		m.stats.Disable()
		m.problem = m.item.AddSubMenuItem("", "")
		m.problem.Disable()
		m.apply = m.item.AddSubMenuItem("Apply configuration changes", "Reconnect with the edited configuration")
		edit := m.item.AddSubMenuItem("Edit configuration", "")
		a.onClick(m.vpn, gen, func() { a.run(name, ipc.AsVPN) })
		a.onClick(m.proxy, gen, func() { a.run(name, ipc.AsProxy) })
		a.onClick(m.off, gen, func() { a.stop(name) })
		a.onClick(m.apply, gen, func() { a.apply(name) })
		a.onClick(edit, gen, func() { a.edit(name) })
		a.menus[name] = m
	}
	systray.AddSeparator()

	a.downAllMI = systray.AddMenuItem("Disconnect all", "")
	a.onClick(a.downAllMI, gen, func() { a.stop("") })
	a.onClick(systray.AddMenuItem("Open configuration folder", ""), gen, a.openFolder)
	a.onClick(systray.AddMenuItem("Import from WireGuard app...", "Copy tunnels from the WireGuard app (asks for administrator rights)"), gen, a.importTunnels)
	a.onClick(systray.AddMenuItem("Show manager log", ""), gen, a.showLog)
	systray.AddSeparator()

	a.bootMI = systray.AddMenuItemCheckbox("Reconnect at boot", "Bring the running tunnels back up when Windows starts", false)
	a.onClick(a.bootMI, gen, a.toggleBoot)
	a.loginMI = systray.AddMenuItemCheckbox("Start splitwire at sign-in", "", runAtLogin())
	a.onClick(a.loginMI, gen, a.toggleLogin)
	a.setupMI = systray.AddMenuItem("Set up splitwire (administrator)...", "Install the splitwire manager service")
	a.setupMI.Hide()
	a.onClick(a.setupMI, gen, a.setup)
	systray.AddSeparator()
	a.onClick(systray.AddMenuItem("Quit", "Close the tray app; running tunnels stay up"), gen, systray.Quit)

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
	return c.Mode.String() + " " + plural(len(c.Apps), "app")
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

// refreshLocked updates icon, tooltip and items from the current state.
func (a *app) refreshLocked() {
	if a.summaryMI == nil {
		return
	}
	st := a.status
	connected := a.link == linkConnected

	icon, summary := "down", ""
	switch a.link {
	case linkConnecting:
		summary = "Connecting to the splitwire manager..."
	case linkMissing:
		summary = "The splitwire manager is not set up"
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
	systray.SetTooltip(truncate("splitwire: "+summary, 120))
	a.summaryMI.SetTitle(truncate(summary, 100))

	for name, m := range a.menus {
		var t *ipc.Tunnel
		if connected {
			t = st.Find(name)
		}
		a.refreshTunnel(name, m, t, a.files[name], connected)
	}

	if connected && len(st.Tunnels) > 0 {
		a.downAllMI.Show()
	} else {
		a.downAllMI.Hide()
	}
	if connected {
		a.bootMI.Enable()
	} else {
		a.bootMI.Disable()
	}
	if connected && st.Boot {
		a.bootMI.Check()
	} else {
		a.bootMI.Uncheck()
	}
	if a.link == linkMissing || a.link == linkFailed {
		a.setupMI.Show()
	} else {
		a.setupMI.Hide()
	}
}

func (a *app) refreshTunnel(name string, m *tunnelMenu, t *ipc.Tunnel, f tunnelFile, connected bool) {
	title := name
	if t != nil {
		title += "  -  " + short(t)
	}
	m.item.SetTitle(title)
	if t.Running() {
		m.item.Check()
	} else {
		m.item.Uncheck()
	}

	vpnTitle, proxyTitle := "VPN", "Proxy"
	if f.cfg != nil {
		vpnTitle = "VPN: " + vpnDetail(f.cfg)
		if f.cfg.Proxy.IsValid() {
			proxyTitle = "Proxy: socks5 and http on " + f.cfg.Proxy.String()
		} else {
			proxyTitle = fmt.Sprintf("Proxy: on a free port from %d", userconf.FirstProxyPort)
		}
		if f.cfg.ProxyVia == config.ViaVPN {
			proxyTitle += ", through the VPN"
		}
	}
	m.vpn.SetTitle(vpnTitle)
	m.proxy.SetTitle(proxyTitle)
	as := ""
	if t.Running() {
		as = t.As
	}
	for _, c := range []struct {
		item *systray.MenuItem
		on   bool
	}{{m.vpn, as == ipc.AsVPN}, {m.proxy, as == ipc.AsProxy}, {m.off, as == ""}} {
		if c.on {
			c.item.Check()
		} else {
			c.item.Uncheck()
		}
		if connected && (f.error == "" || c.item == m.off) {
			c.item.Enable()
		} else {
			c.item.Disable()
		}
	}

	if t != nil && t.State == ipc.StateUp && len(t.Peers) > 0 {
		p := t.Peers[0]
		m.stats.SetTitle(fmt.Sprintf("Handshake %s, received %s, sent %s",
			stats.Ago(p.LastHandshake), stats.Bytes(p.RxBytes), stats.Bytes(p.TxBytes)))
		m.stats.Show()
	} else {
		m.stats.Hide()
	}
	switch {
	case f.error != "":
		m.problem.SetTitle("Configuration problem: " + truncate(f.error, 80))
		m.problem.Show()
	case t != nil && t.State == ipc.StateError:
		m.problem.SetTitle("Failed: " + truncate(t.Error, 80))
		m.problem.Show()
	default:
		m.problem.Hide()
	}
	if t != nil && t.State == ipc.StateUp && f.hash != "" && f.hash != t.ConfigHash {
		m.apply.Show()
	} else {
		m.apply.Hide()
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

func loadTunnel(name string) (text string, c *config.Config, err error) {
	path, err := userconf.Resolve(name)
	if err != nil {
		return "", nil, err
	}
	c, err = config.Load(path)
	if err != nil {
		return "", nil, err
	}
	text, err = c.WithExpandedApps()
	return text, c, err
}

func (a *app) scanTunnels() bool {
	names, _ := userconf.Names()
	files := make(map[string]tunnelFile, len(names))
	for _, n := range names {
		text, c, err := loadTunnel(n)
		if err != nil {
			files[n] = tunnelFile{error: err.Error()}
		} else {
			files[n] = tunnelFile{hash: ipc.ConfigHash(text), cfg: c}
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := strings.Join(names, "\x00") != strings.Join(a.names, "\x00")
	a.names, a.files = names, files
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

// run brings the tunnel up as a VPN or a proxy. A tunnel without a Proxy
// address gets one written to its file first.
func (a *app) run(name, as string) {
	a.mu.Lock()
	t := a.status.Find(name)
	same := t.Running() && t.As == as
	a.mu.Unlock()
	if same {
		return
	}
	if as == ipc.AsProxy {
		path, err := userconf.Resolve(name)
		if err == nil {
			_, err = userconf.EnsureProxy(path)
		}
		if err != nil {
			errorBox("Could not pick a proxy port for %s:\n\n%v", name, err)
			return
		}
	}
	a.connect(name, as)
}

func (a *app) connect(name, as string) {
	text, _, err := loadTunnel(name)
	if err != nil {
		errorBox("%s has a problem:\n\n%v", name, err)
		return
	}
	if _, err := call(ipc.Request{Op: ipc.OpUp, Name: name, As: as, Config: text}); err != nil {
		errorBox("Could not connect %s:\n\n%v", name, err)
	}
}

// stop takes the tunnel down, or every tunnel when name is empty.
func (a *app) stop(name string) {
	a.mu.Lock()
	t := a.status.Find(name)
	a.mu.Unlock()
	if name != "" && t == nil {
		return
	}
	if _, err := call(ipc.Request{Op: ipc.OpDown, Name: name}); err != nil {
		errorBox("Could not disconnect:\n\n%v", err)
	}
}

func (a *app) apply(name string) {
	a.mu.Lock()
	as := ""
	if t := a.status.Find(name); t != nil {
		as = t.As
	}
	a.mu.Unlock()
	if as != "" {
		a.connect(name, as)
	}
}

func (a *app) toggleBoot() {
	a.mu.Lock()
	on := !a.status.Boot
	a.mu.Unlock()
	if _, err := call(ipc.Request{Op: ipc.OpBoot, Boot: on}); err != nil {
		errorBox("Could not change boot start:\n\n%v", err)
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

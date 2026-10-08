package tray

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"splitwire/internal/config"
	"splitwire/internal/ipc"
	"splitwire/internal/svcwait"
	"splitwire/internal/update"
	"splitwire/internal/userconf"
)

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

	// traffic holds the recent counters of running tunnels.
	traffic map[string]*traffic
	// win is the tunnels window, or windowCreating while it opens, and
	// winSelect a tunnel for it to select.
	win       uintptr
	winSelect string
	// openAtStart opens the window once the app is ready.
	openAtStart bool

	// latest is a release newer than this copy, or nil.
	latest *update.Manifest

	setupOnce sync.Once
	// next starts with nextArgs once the menu loop ends.
	next     string
	nextArgs []string
	// image identifies the installed executable this copy runs, or is nil
	// when it runs another.
	image *fileID

	menus       map[string]*tunnelMenu
	summaryMI   *systray.MenuItem
	splitMI     *systray.MenuItem
	splitOffMI  *systray.MenuItem
	vpnsMI      *systray.MenuItem
	proxiesMI   *systray.MenuItem
	downAllMI   *systray.MenuItem
	bootMI      *systray.MenuItem
	loginMI     *systray.MenuItem
	updateMI    *systray.MenuItem
	setupMI     *systray.MenuItem
	uninstallMI *systray.MenuItem
}

func newApp() *app {
	return &app{
		icons: map[string][]byte{
			"down":  icoBytes(colorDown),
			"busy":  icoBytes(colorBusy),
			"up":    icoBytes(colorUp),
			"error": icoBytes(colorError),
		},
		files:   make(map[string]tunnelFile),
		traffic: make(map[string]*traffic),
		retry:   make(chan struct{}, 1),
		menus:   make(map[string]*tunnelMenu),
	}
}

func (a *app) ready() {
	systray.SetIcon(a.icons["down"])
	systray.SetTooltip("SplitWire")
	// A click on the icon opens or closes the window; a right click shows
	// the menu.
	systray.SetOnTapped(func() { go a.toggleWindow() })
	a.scanTunnels()
	a.rebuild()
	go a.watchFolder()
	go a.watchManager()
	go a.watchUpdates()
	// Before setup the install window comes first.
	if a.openAtStart && svcwait.Exists(ipc.ServiceName) {
		go a.openWindow()
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
	a.recordTraffic(st)
	a.refreshLocked()
	a.mu.Unlock()
}

// restartIfReplaced restarts the app into the installed executable when an
// install has replaced the one it runs, which otherwise keeps running from
// the copy moved aside and keeps that copy from being deleted. The window
// stays open when it is. It reports whether the app is restarting.
func (a *app) restartIfReplaced() bool {
	if a.image == nil {
		return false
	}
	installed, err := installedExe()
	if err != nil {
		return false
	}
	if id, err := fileIdentity(installed); err != nil || id == *a.image {
		return false
	}
	a.mu.Lock()
	open := a.win != 0
	a.mu.Unlock()
	a.next, a.nextArgs = installed, nil
	if !open {
		a.nextArgs = []string{backgroundFlag}
	}
	systray.Quit()
	return true
}

// watchManager keeps a watch stream open to the manager, reconnecting when
// the service restarts.
func (a *app) watchManager() {
	var pid uint32
	for {
		if !svcwait.Exists(ipc.ServiceName) {
			a.setLink(linkMissing, "")
			go a.offerSetup()
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
		if a.restartIfReplaced() {
			return
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

// run brings the tunnel up as the Split VPN, a VPN or a proxy. A tunnel
// without a Proxy address gets one written to its file first.
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

// toggle runs the tunnel as as, or takes it down when it already runs that way.
func (a *app) toggle(name, as string) {
	a.mu.Lock()
	t := a.status.Find(name)
	on := t.Running() && t.As == as
	a.mu.Unlock()
	if on {
		a.stop(name)
	} else {
		a.run(name, as)
	}
}

// splitOff takes the Split VPN down.
func (a *app) splitOff() {
	a.mu.Lock()
	name := ""
	for _, t := range a.status.Tunnels {
		if t.As == ipc.AsSplit {
			name = t.Name
		}
	}
	a.mu.Unlock()
	if name != "" {
		a.stop(name)
	}
}

func (a *app) toggleBoot() {
	a.mu.Lock()
	on := !a.status.Boot
	a.mu.Unlock()
	if _, err := call(ipc.Request{Op: ipc.OpBoot, Boot: on}); err != nil {
		errorBox("Could not change reconnecting when Windows starts:\n\n%v", err)
	}
}

func (a *app) openFolder() {
	dir, err := userconf.EnsureDir()
	if err != nil {
		errorBox("%v", err)
		return
	}
	exec.Command("explorer.exe", dir).Start()
}

// logCopy is the file in the temporary folder that shows the manager log.
const logCopy = "splitwire-manager.log"

func (a *app) showLog() {
	rep, err := call(ipc.Request{Op: ipc.OpLog})
	if err != nil {
		errorBox("Could not read the manager log:\n\n%v", err)
		return
	}
	path := filepath.Join(os.TempDir(), logCopy)
	if err := os.WriteFile(path, []byte(strings.Join(rep.Log, "\r\n")+"\r\n"), 0o600); err != nil {
		errorBox("%v", err)
		return
	}
	exec.Command("notepad.exe", path).Start()
}

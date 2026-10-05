package tray

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"splitwire/internal/bootstrap"
	"splitwire/internal/ipc"
	"splitwire/internal/shortcut"
	"splitwire/internal/userconf"
	"splitwire/internal/wgimport"
)

// Version is this executable's version, set by the command.
var Version string

// StartMenuName names the Start menu shortcut to the app.
const StartMenuName = "splitwire"

// deleteArgs hand the deletion of the setup file self to the installed
// copy, which waits for this process to exit first.
func deleteArgs(self string) []string {
	return []string{deleteFlag, self, strconv.Itoa(os.Getpid())}
}

// installedVersion asks the installed copy for its version.
func installedVersion(installed string) string {
	cmd := exec.Command(installed, "version")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimPrefix(strings.TrimSpace(string(out)), "splitwire ")
}

func startMenuExists() bool {
	lnk, err := shortcut.StartMenu(StartMenuName)
	return err == nil && fileExists(lnk)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// bootOn asks the manager whether running tunnels come back at boot.
func bootOn() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	rep, err := ipc.Call(ctx, ipc.Request{Op: ipc.OpStatus})
	return err == nil && rep.Status != nil && rep.Status.Boot
}

// installPlan is what the install window decided.
type installPlan struct {
	args       []string // manager install arguments
	signIn     bool
	deleteSelf bool
}

// installWindow shows every install choice in one window, filled in from
// the current state when updating. It reports false when canceled.
func installWindow(self, installed string, updating bool) (installPlan, bool) {
	names, _ := userconf.Names()
	dir, _ := userconf.Dir()
	driverPath, _ := bootstrap.DriverPath()
	type choice struct {
		option
		on, off string // manager install flags for checked and unchecked
	}
	choices := []choice{
		{option{
			label:   "Add splitwire to the Start menu",
			detail:  "A shortcut for every user on this PC, removed again on uninstall.",
			checked: !updating || startMenuExists(),
		}, "--start-menu", "--no-start-menu"},
		{option: option{
			label: "Start splitwire at sign-in",
			detail: "Opens this notification area app when you sign in. Tunnels run in the " +
				"background service either way.",
			checked: !updating || runAtLogin(),
		}},
		{option{
			label: "Reconnect tunnels at boot",
			detail: "Brings back the tunnels that were running when Windows starts, before " +
				"anyone signs in.",
			checked: updating && bootOn(),
		}, "--boot", "--no-boot"},
	}
	const signIn = 1
	if !fileExists(driverPath) {
		choices = append(choices, choice{option{
			label: "Install the split tunnel driver now",
			detail: "Mullvad's signed driver behind include and exclude modes, downloaded " +
				"from mullvad.net. Without this, it installs when such a tunnel first connects.",
			checked: true,
		}, "--drivers", ""})
	}
	if wgimport.AppInstalled() {
		choices = append(choices, choice{option{
			label: "Import tunnels from the WireGuard app",
			detail: "Copies its tunnels into " + dir + ". The WireGuard app keeps its own " +
				"copies, and existing files here stay.",
			checked: len(names) == 0,
		}, "--import", ""})
	}
	deleteAt := -1
	if !samePath(self, installed) {
		deleteAt = len(choices)
		choices = append(choices, choice{option: option{
			label:   "Delete this file afterward",
			detail:  self + "\nsplitwire then runs from Program Files.",
			checked: true,
		}})
	}

	title, button := "Install splitwire", "Install"
	intro := "splitwire installs into Program Files with a background service that connects " +
		"tunnels without further prompts. Windows asks for administrator rights once."
	if updating {
		title, button = "Update splitwire", "Update"
		intro = fmt.Sprintf("Update the installed splitwire (version %s) to this copy (version %s). "+
			"Running tunnels reconnect. Windows asks for administrator rights once.",
			installedVersion(installed), Version)
	}
	opts := make([]option, len(choices))
	for i, c := range choices {
		opts[i] = c.option
	}
	states, ok := askOptions(title, intro, opts, button)
	if !ok {
		return installPlan{}, false
	}
	plan := installPlan{args: []string{"manager", "install"}, signIn: states[signIn]}
	for i, c := range choices {
		switch {
		case states[i] && c.on != "":
			plan.args = append(plan.args, c.on)
		case !states[i] && c.off != "":
			plan.args = append(plan.args, c.off)
		}
	}
	plan.deleteSelf = deleteAt >= 0 && states[deleteAt]
	return plan, true
}

// install runs the plan: the elevated manager install, then the sign-in
// entry. It reports whether the install succeeded.
func (p installPlan) install(self string) bool {
	if !runElevated(self, p.args...) {
		return false
	}
	if err := setRunAtLogin(p.signIn); err != nil {
		errorBox("Could not change start at sign-in:\n\n%v", err)
	}
	return true
}

// handOver runs the installed copy instead of this one, offering to update
// it to this copy when they differ.
func handOver(self, installed string) error {
	var next []string
	if !sameContent(self, installed) {
		if plan, ok := installWindow(self, installed, true); ok {
			if !plan.install(self) {
				return nil
			}
			if err := quitRunningTray(); err != nil {
				errorBox("%v", err)
				return nil
			}
			if plan.deleteSelf {
				next = deleteArgs(self)
			}
		}
	}
	if trayRunning() {
		return nil
	}
	return startTray(installed, next...)
}

// offerSetup shows the install window once per run when the manager
// service is missing. Without the service the app can do nothing, so it
// quits when the window is canceled or the install does not complete.
func (a *app) offerSetup() {
	a.setupOnce.Do(func() {
		if !a.install() {
			systray.Quit()
		}
	})
}

// setup is the menu's Set up item: the install window, leaving the app
// running when canceled.
func (a *app) setup() { a.install() }

// install installs splitwire from the install window's choices and
// switches to the installed copy. It reports whether the install
// completed.
func (a *app) install() bool {
	self := selfExe()
	installed, err := installedExe()
	if err != nil {
		errorBox("%v", err)
		return false
	}
	plan, ok := installWindow(self, installed, false)
	if !ok || !plan.install(self) {
		return false
	}
	if !samePath(self, installed) {
		a.next = installed
		if plan.deleteSelf {
			a.nextArgs = deleteArgs(self)
		}
		systray.Quit()
		return true
	}
	a.refreshLogin()
	select {
	case a.retry <- struct{}{}:
	default:
	}
	return true
}

func (a *app) uninstall() {
	dir, _ := userconf.Dir()
	opts := []option{{
		label: "Delete my tunnel configurations",
		detail: "Deletes " + dir + " and the private keys in it. Leave this off to set " +
			"splitwire up again later or to use the files elsewhere.",
	}}
	if wgimport.AppInstalled() {
		opts = append(opts, option{
			label:    "Remove the WireGuardNT driver",
			detail:   "The WireGuard app is installed and uses this driver, so it stays.",
			disabled: true,
		})
	} else {
		opts = append(opts, option{
			label:   "Remove the WireGuardNT driver",
			detail:  "The kernel driver behind VPN tunnels, installed by wireguard.dll on first use.",
			checked: true,
		})
	}
	states, ok := askOptions("Uninstall splitwire",
		"This disconnects every tunnel and removes splitwire's services, Mullvad's split "+
			"tunnel driver, its firewall entries, Program Files\\splitwire, the Start menu "+
			"shortcut and the sign-in entry. A split tunnel driver the Mullvad VPN app "+
			"installed stays. Files in use go at the next restart. Windows asks for "+
			"administrator rights.",
		opts, "Uninstall")
	if !ok {
		return
	}
	args := []string{"cleanup"}
	if states[0] {
		args = append(args, "--configs")
	}
	if !states[1] {
		args = append(args, "--keep-wireguardnt")
	}
	if !runElevated(selfExe(), args...) {
		return
	}
	setRunAtLogin(false)
	systray.Quit()
}

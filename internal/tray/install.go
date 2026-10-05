package tray

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"fyne.io/systray"
	"golang.org/x/sys/windows"

	"splitwire/internal/userconf"
	"splitwire/internal/wgimport"
)

// Version is this executable's version, set by the command.
var Version string

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

// handOver runs the installed copy instead of this one, offering to update
// it to this copy when they differ.
func handOver(self, installed string) error {
	var next []string
	if !sameContent(self, installed) {
		intro := fmt.Sprintf("Update the installed splitwire (version %s) to this copy (version %s)?\n\n"+
			"Running tunnels reconnect. Windows asks for administrator rights.", installedVersion(installed), Version)
		states, ok := askOptions("Update splitwire", intro, []option{{
			label:   "Delete this file after updating",
			detail:  self + "\nThe installed copy in Program Files stays.",
			checked: true,
		}}, "Update")
		if ok {
			if !runElevated(self, "manager", "install") {
				return nil
			}
			if err := quitRunningTray(); err != nil {
				errorBox("%v", err)
				return nil
			}
			if states[0] {
				next = deleteArgs(self)
			}
		}
	}
	if trayRunning() {
		return nil
	}
	return startTray(installed, next...)
}

// offerSetup shows the setup dialog once per run when the manager service
// is missing.
func (a *app) offerSetup() {
	a.setupOnce.Do(a.setup)
}

// setup asks for the install options, installs the manager service and
// this executable, and switches to the installed copy.
func (a *app) setup() {
	self := selfExe()
	installed, err := installedExe()
	if err != nil {
		errorBox("%v", err)
		return
	}
	names, _ := userconf.Names()
	dir, _ := userconf.Dir()
	opts := []option{
		{
			label:   "Add splitwire to the Start menu",
			detail:  "A shortcut for every user on this PC, removed again on uninstall.",
			checked: true,
		},
		{
			label: "Start splitwire at sign-in",
			detail: "Opens this notification area app when you sign in. Tunnels run in the " +
				"background service either way.",
			checked: true,
		},
		{
			label: "Reconnect tunnels at boot",
			detail: "Brings back the tunnels that were running when Windows starts, before " +
				"anyone signs in. The menu changes this later.",
		},
	}
	const startMenu, signIn, boot = 0, 1, 2
	importAt, deleteAt := -1, -1
	if wgimport.AppInstalled() {
		importAt = len(opts)
		opts = append(opts, option{
			label: "Import tunnels from the WireGuard app",
			detail: "Copies its tunnels into " + dir + ". The WireGuard app keeps its own " +
				"copies, and existing files here stay.",
			checked: len(names) == 0,
		})
	}
	if !samePath(self, installed) {
		deleteAt = len(opts)
		opts = append(opts, option{
			label:   "Delete this setup file afterward",
			detail:  self + "\nsplitwire then runs from Program Files.",
			checked: true,
		})
	}
	states, ok := askOptions("Set up splitwire",
		"splitwire installs into Program Files with a background service that connects "+
			"tunnels without further prompts. Windows asks for administrator rights once.",
		opts, "Install")
	if !ok {
		return
	}

	args := []string{"manager", "install"}
	if states[startMenu] {
		args = append(args, "--start-menu")
	}
	if states[boot] {
		args = append(args, "--boot")
	}
	if importAt >= 0 && states[importAt] {
		args = append(args, "--import")
	}
	if !runElevated(self, args...) {
		return
	}
	if err := setRunAtLogin(states[signIn]); err != nil {
		errorBox("Could not change start at sign-in:\n\n%v", err)
	}
	if !samePath(self, installed) {
		a.next = installed
		if deleteAt >= 0 && states[deleteAt] {
			a.nextArgs = deleteArgs(self)
		}
		systray.Quit()
		return
	}
	a.refreshLogin()
	select {
	case a.retry <- struct{}{}:
	default:
	}
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
		"This disconnects every tunnel and removes splitwire's services, the split tunnel "+
			"driver, its firewall entries, Program Files\\splitwire, the Start menu shortcut "+
			"and the sign-in entry. Files in use go at the next restart. Windows asks for "+
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

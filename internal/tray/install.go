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
const StartMenuName = "SplitWire"

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

// driversNote credits the drivers every install puts in place.
const driversNote = "Also installs the WireGuard driver (WireGuardNT, wireguard.com) and " +
	"Mullvad's open source split tunnel driver (mullvad.net)."

// installPlan is what the install window decided.
type installPlan struct {
	args       []string // manager install arguments
	startMenu  bool
	signIn     bool
	deleteSelf bool
}

// installWindow shows every install choice in one window, grouped and
// filled in from the current state when updating. It reports false when
// canceled.
func installWindow(self, installed string, updating bool) (installPlan, bool) {
	names, _ := userconf.Names()
	type choice struct {
		option
		key     string // names the choices the app applies itself
		on, off string // manager install flags for checked and unchecked
	}
	choices := []choice{{
		option: option{
			heading: "Install",
			label:   "Add SplitWire to the Start menu",
			detail:  "Your account only.",
			checked: !updating || startMenuExists(),
		},
		key: "startMenu",
	}}
	if wgimport.AppInstalled() {
		choices = append(choices, choice{option: option{
			label:   "Import tunnels from the WireGuard app",
			detail:  `Copies them to %APPDATA%\splitwire. The app keeps its own.`,
			checked: len(names) == 0,
		}, on: "--import"})
	}
	if !samePath(self, installed) {
		choices = append(choices, choice{option: option{
			label:   "Delete this file afterward",
			detail:  self,
			checked: true,
		}, key: "delete"})
	}
	choices = append(choices,
		choice{option: option{
			heading: "Startup",
			label:   "Start SplitWire at sign-in",
			detail:  "Opens this app in the notification area.",
			checked: !updating || runAtLogin(),
		}, key: "signIn"},
		choice{option: option{
			label:   "Reconnect tunnels when Windows starts",
			detail:  "Brings back running tunnels before anyone signs in.",
			checked: updating && bootOn(),
		}, on: "--boot", off: "--no-boot"},
	)

	title, button := "Install SplitWire", "Install"
	intro := "Installs SplitWire into Program Files with a background service, so tunnels " +
		"connect without prompts.\n\n" + driversNote
	if updating {
		title, button = "Update SplitWire", "Update"
		intro = fmt.Sprintf("Updates SplitWire from version %s to %s. Running tunnels reconnect.",
			installedVersion(installed), Version)
		if !bootstrap.WireGuardNTInstalled() || !bootstrap.SplitDriverInstalled() {
			intro += "\n\n" + driversNote
		}
	}
	opts := make([]option, len(choices))
	for i, c := range choices {
		opts[i] = c.option
	}
	states, ok := askOptions(title, intro, opts, button)
	if !ok {
		return installPlan{}, false
	}
	plan := installPlan{args: []string{"manager", "install", "--wireguard-driver", "--split-tunnel-driver"}}
	if sid, err := ownSID(); err == nil {
		plan.args = append(plan.args, "--user="+sid)
	}
	for i, c := range choices {
		switch c.key {
		case "startMenu":
			plan.startMenu = states[i]
		case "signIn":
			plan.signIn = states[i]
		case "delete":
			plan.deleteSelf = states[i]
		}
		switch {
		case states[i] && c.on != "":
			plan.args = append(plan.args, c.on)
		case !states[i] && c.off != "":
			plan.args = append(plan.args, c.off)
		}
	}
	return plan, true
}

// install runs the plan: the elevated manager install, then the Start
// menu shortcut and sign-in entry, which belong to the user. It reports
// whether the install succeeded.
func (p installPlan) install(self string) bool {
	if !runElevated(self, p.args...) {
		return false
	}
	if err := setStartMenu(p.startMenu); err != nil {
		errorBox("Could not change the Start menu shortcut:\n\n%v", err)
	}
	if err := setRunAtLogin(p.signIn); err != nil {
		errorBox("Could not change start at sign-in:\n\n%v", err)
	}
	return true
}

// ownSID is the SID of the user the app runs as, which stays the same when
// the elevated install runs under another account's password.
func ownSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// setStartMenu adds the installed app to the user's Start menu, or removes
// it.
func setStartMenu(on bool) error {
	lnk, err := shortcut.StartMenu(StartMenuName)
	if err != nil {
		return err
	}
	// Saving over a shortcut keeps its file name's letter case, so the
	// shortcut is made anew.
	if err := os.Remove(lnk); err != nil && !os.IsNotExist(err) {
		return err
	}
	if !on {
		return nil
	}
	installed, err := installedExe()
	if err != nil {
		return err
	}
	return shortcut.Create(lnk, installed, Command, "VPN client with per-app split tunneling")
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
		showRunningTray()
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
	a.mu.Lock()
	others := a.status.Users - 1
	a.mu.Unlock()
	var opts []option
	if others > 0 {
		opts = append(opts, option{
			heading: "Other users",
			label:   fmt.Sprintf("Keep SplitWire for the %s", plural(others, "other user")),
			detail:  "Removes only your access, Start menu shortcut and sign-in entry.",
			checked: true,
		})
	}
	opts = append(opts, option{
		heading: "Your files",
		label:   "Delete my tunnel configurations",
		detail:  `%APPDATA%\splitwire, including your private keys.`,
	})
	if wgimport.AppInstalled() {
		opts = append(opts, option{
			heading:  "Drivers",
			label:    "Remove the WireGuard driver",
			detail:   "Stays: the WireGuard app uses it.",
			disabled: true,
		})
	} else {
		opts = append(opts, option{
			heading: "Drivers",
			label:   "Remove the WireGuard driver",
			detail:  "WireGuardNT from wireguard.com, unless SplitWire stays for others.",
			checked: true,
		})
	}
	states, ok := askOptions("Uninstall SplitWire",
		"Disconnects every tunnel and removes SplitWire, its service and its firewall entries.",
		opts, "Uninstall")
	if !ok {
		return
	}
	keep := others > 0 && states[0]
	configs, wireguardNT := states[len(states)-2], states[len(states)-1]
	if keep {
		sid, err := ownSID()
		if err != nil {
			errorBox("%v", err)
			return
		}
		if !runElevated(selfExe(), "manager", "leave", "--user="+sid) {
			return
		}
		if configs {
			if dir, err := userconf.Dir(); err == nil {
				if err := os.RemoveAll(dir); err != nil {
					errorBox("Could not delete your tunnel configurations:\n\n%v", err)
				}
			}
		}
	} else {
		args := []string{"cleanup"}
		if configs {
			args = append(args, "--configs")
		}
		if !wireguardNT {
			args = append(args, "--keep-wireguardnt")
		}
		if !runElevated(selfExe(), args...) {
			return
		}
	}
	setStartMenu(false)
	setRunAtLogin(false)
	systray.Quit()
}

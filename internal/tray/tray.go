// Package tray is the notification area app. It runs as the signed-in user
// and drives the splitwire manager service.
package tray

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"splitwire/internal/bootstrap"
	"splitwire/internal/elevate"
)

// Command is the CLI command that starts the tray app.
const Command = "tray"

const (
	instanceMutex = `Local\splitwire-tray`
	// quitEvent asks the running tray app to exit, so a new copy can
	// replace it.
	quitEvent = `Local\splitwire-tray-quit`
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue  = "splitwire"
)

// deleteFlag passes the installed copy a setup file to delete, and the
// process ID to wait for before deleting it.
const deleteFlag = "--delete-setup"

// Run starts the tray app. A copy run from outside the install root hands
// over to the installed copy, updating it first when the two differ.
func Run(args []string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	installed, err := installedExe()
	if err != nil {
		return err
	}
	if !samePath(self, installed) {
		if _, err := os.Stat(installed); err == nil {
			return handOver(self, installed)
		}
	}
	if len(args) == 3 && args[0] == deleteFlag {
		if pid, err := strconv.ParseUint(args[2], 10, 32); err == nil {
			go deleteSetup(args[1], uint32(pid), installed)
		}
	}

	if runAtLogin() {
		setRunAtLogin(true)
	}
	mutex, owned, err := takeMutex()
	if err != nil {
		return err
	}
	if !owned {
		windows.CloseHandle(mutex)
		return nil
	}
	a := newApp()
	if quit, err := createQuitEvent(); err == nil {
		defer windows.CloseHandle(quit)
		go func() {
			windows.WaitForSingleObject(quit, windows.INFINITE)
			systray.Quit()
		}()
	}
	systray.Run(a.ready, func() {})
	// Closing the last handle deletes the mutex, so the next copy can claim it.
	windows.ReleaseMutex(mutex)
	windows.CloseHandle(mutex)
	if a.next != "" {
		return startTray(a.next, a.nextArgs...)
	}
	return nil
}

// offerDelete asks whether to delete the setup file self now that the
// installed copy runs, and returns the arguments that hand the deletion to
// the installed copy.
func offerDelete(self string) []string {
	if !ask("splitwire is installed in Program Files.\n\nDelete the setup file?\n\n" + self) {
		return nil
	}
	return []string{deleteFlag, self, strconv.Itoa(os.Getpid())}
}

// deleteSetup deletes the setup file at path once the process that ran it
// has exited. It deletes only a file identical to the installed copy.
func deleteSetup(path string, pid uint32, installed string) {
	if p, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid); err == nil {
		windows.WaitForSingleObject(p, windows.INFINITE)
		windows.CloseHandle(p)
	}
	if samePath(path, installed) || !sameContent(path, installed) {
		return
	}
	if err := os.Remove(path); err != nil {
		errorBox("Could not delete the setup file:\n\n%v", err)
	}
}

func installedExe() (string, error) {
	bin, err := bootstrap.BinDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(bin, "splitwire.exe"), nil
}

func samePath(a, b string) bool {
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b))
}

func sameContent(a, b string) bool {
	x, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	y, err := os.ReadFile(b)
	return err == nil && bytes.Equal(x, y)
}

// takeMutex claims the single tray instance. It reports false when another
// tray app holds it.
func takeMutex() (windows.Handle, bool, error) {
	name, _ := windows.UTF16PtrFromString(instanceMutex)
	h, err := windows.CreateMutex(nil, true, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return h, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return h, true, nil
}

func createQuitEvent() (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString(quitEvent)
	return windows.CreateEvent(nil, 0, 0, name)
}

// mutexModifyState is the MUTEX_MODIFY_STATE access right.
const mutexModifyState = 0x0001

// quitRunningTray asks a running tray app to exit and waits until it has.
func quitRunningTray() error {
	mname, _ := windows.UTF16PtrFromString(instanceMutex)
	m, err := windows.OpenMutex(windows.SYNCHRONIZE|mutexModifyState, false, mname)
	if err != nil {
		return nil // none running
	}
	defer windows.CloseHandle(m)
	ev, err := createQuitEvent()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(ev)
	if err := windows.SetEvent(ev); err != nil {
		return err
	}
	r, err := windows.WaitForSingleObject(m, uint32((30 * time.Second).Milliseconds()))
	if r == windows.WAIT_OBJECT_0 || r == windows.WAIT_ABANDONED {
		windows.ReleaseMutex(m)
		return nil
	}
	if err == nil {
		err = errors.New("the running splitwire tray app did not exit; quit it from its menu and try again")
	}
	return err
}

func trayRunning() bool {
	name, _ := windows.UTF16PtrFromString(instanceMutex)
	m, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name)
	if err != nil {
		return false
	}
	windows.CloseHandle(m)
	return true
}

func startTray(exe string, args ...string) error {
	return exec.Command(exe, append([]string{Command}, args...)...).Start()
}

// handOver runs the installed copy instead of this one, offering to update
// it to this copy when they differ, and then to delete this copy.
func handOver(self, installed string) error {
	var deleteArgs []string
	if !sameContent(self, installed) {
		if ask("This copy of splitwire differs from the installed one.\n\n" +
			"Update the installed splitwire to this copy? Running tunnels reconnect, " +
			"and Windows asks for administrator rights.") {
			if !runElevated(self, "manager", "install") {
				return nil
			}
			if err := quitRunningTray(); err != nil {
				errorBox("%v", err)
				return nil
			}
			deleteArgs = offerDelete(self)
		}
	}
	if trayRunning() {
		return nil
	}
	return startTray(installed, deleteArgs...)
}

// ---- dialogs ----

func errorBox(format string, args ...any) {
	text, _ := windows.UTF16PtrFromString(fmt.Sprintf(format, args...))
	caption, _ := windows.UTF16PtrFromString("splitwire")
	windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
}

func ask(text string) bool {
	t, _ := windows.UTF16PtrFromString(text)
	caption, _ := windows.UTF16PtrFromString("splitwire")
	r, _ := windows.MessageBox(0, t, caption, windows.MB_YESNO|windows.MB_ICONQUESTION|windows.MB_SETFOREGROUND)
	return r == idYes
}

// askNo asks a yes or no question with No as the default button.
func askNo(text string) bool {
	t, _ := windows.UTF16PtrFromString(text)
	caption, _ := windows.UTF16PtrFromString("splitwire")
	r, _ := windows.MessageBox(0, t, caption, windows.MB_YESNO|windows.MB_ICONWARNING|mbDefButton2|windows.MB_SETFOREGROUND)
	return r == idYes
}

// MessageBox values.
const (
	idYes        = 6
	mbDefButton2 = 0x00000100
)

// runElevated runs a CLI command of exe elevated in a console window that
// stays open on failure, so its error is readable there. It reports
// whether the command succeeded.
func runElevated(exe string, args ...string) bool {
	code, err := elevate.RunWait(exe, append([]string{elevate.HoldOnErrorFlag}, args...), true)
	if err != nil {
		errorBox("%v", err)
		return false
	}
	return code == 0
}

func selfExe() string {
	self, _ := os.Executable()
	return self
}

// ---- setup and uninstall ----

func (a *app) importTunnels() { runElevated(selfExe(), "import") }

// offerSetup asks once per run to set splitwire up when the manager
// service is missing.
func (a *app) offerSetup() {
	a.setupOnce.Do(func() {
		if ask("Set up splitwire?\n\n" +
			"It installs into Program Files with a background service that connects " +
			"tunnels without further prompts, and starts at sign-in. Windows asks " +
			"for administrator rights once.") {
			a.setup()
		}
	})
}

// setup installs the manager service and this executable, turns on start
// at sign-in, and switches to the installed copy.
func (a *app) setup() {
	if !runElevated(selfExe(), "manager", "install") {
		return
	}
	installed, err := installedExe()
	if err != nil {
		errorBox("%v", err)
		return
	}
	if err := setRunAtLogin(true); err != nil {
		errorBox("Could not turn on start at sign-in:\n\n%v", err)
	}
	if !samePath(selfExe(), installed) {
		a.next = installed
		a.nextArgs = offerDelete(selfExe())
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
	if !ask("Uninstall splitwire?\n\n" +
		"This disconnects every tunnel and removes everything splitwire installed: " +
		"its services, the split tunnel driver, its firewall objects, " +
		"Program Files\\splitwire and the sign-in entry. The WireGuardNT driver " +
		"stays when the WireGuard app is installed. Windows asks for administrator rights.") {
		return
	}
	args := []string{"cleanup"}
	if askNo("Also delete your tunnel configurations in %APPDATA%\\splitwire?\n\n" +
		"They hold your private keys. Keep them to set splitwire up again later " +
		"or to import them elsewhere.") {
		args = append(args, "--configs")
	}
	if !runElevated(selfExe(), args...) {
		return
	}
	setRunAtLogin(false)
	systray.Quit()
}

// ---- start at sign-in ----

func runAtLogin() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runValue)
	return err == nil
}

// setRunAtLogin starts the installed copy, or this one when none is
// installed, at sign-in.
func setRunAtLogin(on bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue(runValue); err != nil && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return err
		}
		return nil
	}
	exe := selfExe()
	if installed, err := installedExe(); err == nil {
		if _, err := os.Stat(installed); err == nil {
			exe = installed
		}
	}
	return k.SetStringValue(runValue, windows.EscapeArg(exe)+" "+Command)
}

// RemoveRunAtLogin deletes the sign-in entry.
func RemoveRunAtLogin() error { return setRunAtLogin(false) }

// RemoveTempFiles deletes the app's files in the temporary folder: the
// copied manager log and the icons the menu library writes there.
func RemoveTempFiles() {
	tmp := os.TempDir()
	os.Remove(filepath.Join(tmp, logCopy))
	icons, _ := filepath.Glob(filepath.Join(tmp, "systray_temp_icon_*"))
	for _, p := range icons {
		os.Remove(p)
	}
}

func (a *app) toggleLogin() {
	if err := setRunAtLogin(!runAtLogin()); err != nil {
		errorBox("%v", err)
	}
	a.refreshLogin()
}

func (a *app) refreshLogin() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if runAtLogin() {
		a.loginMI.Check()
	} else {
		a.loginMI.Uncheck()
	}
}

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
	"splitwire/internal/ipc"
	"splitwire/internal/svcwait"
)

// Command is the CLI command that starts the tray app.
const Command = "tray"

const (
	instanceMutex = `Local\splitwire-tray`
	// quitEvent asks the running tray app to exit, so a new copy can
	// replace it, and openEvent asks it to show its window.
	quitEvent = `Local\splitwire-tray-quit`
	openEvent = `Local\splitwire-tray-open`
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	runValue  = "splitwire"
)

// deleteFlag passes the installed copy a setup file to delete, and the
// process ID to wait for before deleting it.
const deleteFlag = "--delete-setup"

// backgroundFlag starts the app without its window, as at sign-in.
const backgroundFlag = "--background"

// Run starts the tray app and opens its window, unless args start it in
// the background. A copy run from outside the install root hands over to
// the installed copy, updating it first when the two differ. A copy run
// while the app runs has the running app show its window.
func Run(args []string) error {
	followSystemTheme()
	background := len(args) > 0 && args[0] == backgroundFlag
	if background {
		args = args[1:]
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	installed, err := installedExe()
	if err != nil {
		return err
	}
	// An installed copy without the manager service is one an uninstall
	// left for deletion at the next restart.
	if !samePath(self, installed) && fileExists(installed) && svcwait.Exists(ipc.ServiceName) {
		return handOver(self, installed)
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
		if !background {
			showRunningTray()
		}
		return nil
	}
	a := newApp()
	a.openAtStart = !background
	if samePath(self, installed) {
		if id, err := fileIdentity(installed); err == nil {
			a.image = &id
		}
	}
	if quit, err := createEvent(quitEvent); err == nil {
		defer windows.CloseHandle(quit)
		go func() {
			windows.WaitForSingleObject(quit, windows.INFINITE)
			systray.Quit()
		}()
	}
	if open, err := createEvent(openEvent); err == nil {
		defer windows.CloseHandle(open)
		go func() {
			for {
				if r, _ := windows.WaitForSingleObject(open, windows.INFINITE); r != windows.WAIT_OBJECT_0 {
					return
				}
				a.openWindow()
			}
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

func installedExe() (string, error) { return bootstrap.ExePath() }

// fileID identifies a file, which keeps its identity when renamed.
type fileID struct{ volume, high, low uint32 }

func fileIdentity(path string) (fileID, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fileID{}, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fileID{}, err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fileID{}, err
	}
	return fileID{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, nil
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

// createEvent opens the named auto-reset event, creating it if needed.
func createEvent(event string) (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString(event)
	return windows.CreateEvent(nil, 0, 0, name)
}

// showRunningTray asks the running tray app to show its window.
func showRunningTray() {
	if ev, err := createEvent(openEvent); err == nil {
		windows.SetEvent(ev)
		windows.CloseHandle(ev)
	}
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
	ev, err := createEvent(quitEvent)
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
		err = errors.New("the running SplitWire tray app did not exit; quit it from its menu and try again")
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

// ---- dialogs ----

func infoBox(format string, args ...any) {
	text, _ := windows.UTF16PtrFromString(fmt.Sprintf(format, args...))
	caption, _ := windows.UTF16PtrFromString("SplitWire")
	windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONINFORMATION|windows.MB_SETFOREGROUND)
}

func errorBox(format string, args ...any) {
	text, _ := windows.UTF16PtrFromString(fmt.Sprintf(format, args...))
	caption, _ := windows.UTF16PtrFromString("SplitWire")
	windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
}

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
	return k.SetStringValue(runValue, windows.EscapeArg(exe)+" "+Command+" "+backgroundFlag)
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

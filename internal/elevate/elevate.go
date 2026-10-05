// Package elevate detects and requests administrator rights.
package elevate

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// HoldFlag makes an elevated relaunch wait for Enter before its console
// window closes.
const HoldFlag = "--hold"

// IsElevated reports whether the process runs with administrator rights.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Relaunch starts this executable elevated with args through the UAC prompt.
// The new process gets its own console window.
func Relaunch(args []string, hold bool) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if hold {
		args = append([]string{HoldFlag}, args...)
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = windows.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	dir, _ := windows.UTF16PtrFromString(cwd)
	if err := windows.ShellExecute(0, verb, file, params, dir, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("request administrator rights: %w", err)
	}
	return nil
}

// WaitForEnter keeps an elevated console window open until the user reads it.
func WaitForEnter() {
	fmt.Fprint(os.Stderr, "\nPress Enter to close this window.")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// Command splitwire-tray is the notification area app for splitwire. It runs
// as the signed-in user and drives the splitwire manager service.
package main

import (
	"errors"
	"os"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
)

var procSetProcessDpiAwarenessContext = windows.NewLazySystemDLL("user32.dll").NewProc("SetProcessDpiAwarenessContext")

const dpiAwarenessPerMonitorV2 = ^uintptr(3) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 (-4)

func main() {
	name, _ := windows.UTF16PtrFromString(`Local\splitwire-tray`)
	mutex, err := windows.CreateMutex(nil, true, name)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		os.Exit(0)
	}
	defer windows.CloseHandle(mutex)

	if procSetProcessDpiAwarenessContext.Find() == nil {
		procSetProcessDpiAwarenessContext.Call(dpiAwarenessPerMonitorV2)
	}

	a := newApp()
	systray.Run(a.ready, func() {})
}

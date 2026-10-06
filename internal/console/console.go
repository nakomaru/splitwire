// Package console tells how the process was started and gives it a console
// window when it needs one. The executable's manifest sets the console
// allocation policy to detached, so Windows 11 24H2 and later start it
// without a console unless a shell's console is there to inherit.
package console

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleProcessList = kernel32.NewProc("GetConsoleProcessList")
	procAllocConsole          = kernel32.NewProc("AllocConsole")
	procFreeConsole           = kernel32.NewProc("FreeConsole")
	procGetConsoleWindow      = kernel32.NewProc("GetConsoleWindow")
)

// Kind is how the process relates to a console.
type Kind int

const (
	// None: started without a console, as from Explorer on Windows 11 24H2
	// and later.
	None Kind = iota
	// Own: Windows created a console for this process alone, as from
	// Explorer on earlier Windows.
	Own
	// Shared: attached to a shell's console.
	Shared
)

// Current reports the process's console.
func Current() Kind {
	var pids [2]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	switch n {
	case 0:
		return None
	case 1:
		return Own
	}
	return Shared
}

// Hidden reports a console without a window, as a program started with
// CREATE_NO_WINDOW has, such as a script runner's or an agent's command.
// Terminals, Windows Terminal's pseudoconsoles among them, have a window.
func Hidden() bool {
	if Current() == None {
		return false
	}
	w, _, _ := procGetConsoleWindow.Call()
	return w == 0
}

// Free detaches from the console, closing a console window of its own.
func Free() { procFreeConsole.Call() }

// Ensure opens a console window when the process has none and points the
// standard streams at it.
func Ensure() error {
	if Current() != None {
		return nil
	}
	if r, _, err := procAllocConsole.Call(); r == 0 {
		return err
	}
	out, err := open("CONOUT$")
	if err != nil {
		return err
	}
	in, err := open("CONIN$")
	if err != nil {
		return err
	}
	windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, out)
	windows.SetStdHandle(windows.STD_ERROR_HANDLE, out)
	windows.SetStdHandle(windows.STD_INPUT_HANDLE, in)
	os.Stdout = os.NewFile(uintptr(out), "/dev/stdout")
	os.Stderr = os.NewFile(uintptr(out), "/dev/stderr")
	os.Stdin = os.NewFile(uintptr(in), "/dev/stdin")
	return nil
}

func open(name string) (windows.Handle, error) {
	p, _ := windows.UTF16PtrFromString(name)
	return windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

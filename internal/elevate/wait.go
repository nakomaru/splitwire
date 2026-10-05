package elevate

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// HoldOnErrorFlag makes an elevated relaunch wait for Enter only when the
// command fails.
const HoldOnErrorFlag = "--hold-on-error"

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

const seeMaskNoCloseProcess = 0x00000040

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

// RunWait runs exe elevated with args through the UAC prompt and waits for
// it to exit, returning its exit code. A declined prompt is an error.
func RunWait(exe string, args []string, show bool) (uint32, error) {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = windows.EscapeArg(a)
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	cwd, _ := os.Getwd()
	dir, _ := windows.UTF16PtrFromString(cwd)
	info := shellExecuteInfo{
		fMask:        seeMaskNoCloseProcess,
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		lpDirectory:  dir,
		nShow:        windows.SW_HIDE,
	}
	if show {
		info.nShow = windows.SW_SHOWNORMAL
	}
	info.cbSize = uint32(unsafe.Sizeof(info))
	if r, _, err := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return 0, fmt.Errorf("request administrator rights: %w", err)
	}
	if info.hProcess == 0 {
		return 0, nil
	}
	defer windows.CloseHandle(info.hProcess)
	if _, err := windows.WaitForSingleObject(info.hProcess, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.hProcess, &code); err != nil {
		return 0, err
	}
	return code, nil
}

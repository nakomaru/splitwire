package bootstrap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows renames a running executable but neither deletes nor replaces it,
// so replacing the installed executable moves the running copy aside to
// dst.old, or dst.old1 and so on while an older copy there still runs.

// asidePath deletes the copies of dst moved aside that no process runs
// anymore, and returns a free name to move dst to.
func asidePath(dst string) string {
	removeAside(dst)
	aside := dst + ".old"
	for i := 1; ; i++ {
		if _, err := os.Lstat(aside); os.IsNotExist(err) {
			return aside
		}
		aside = fmt.Sprintf("%s.old%d", dst, i)
	}
}

// removeAside deletes the copies of dst moved aside, and returns those it
// could not delete with the first error.
func removeAside(dst string) (left []string, err error) {
	dir, base := filepath.Split(dst)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), base+".old") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if rerr := os.Remove(p); rerr != nil && !os.IsNotExist(rerr) {
			left = append(left, p)
			if err == nil {
				err = rerr
			}
		}
	}
	return left, err
}

// DeleteAside deletes the copies of the installed executable moved aside,
// each as soon as the last process running it exits. It returns once none
// is left, or when one stays that no process holds.
func DeleteAside() error {
	dst, err := ExePath()
	if err != nil {
		return err
	}
	return deleteAside(dst)
}

func deleteAside(dst string) error {
	unheld := false
	for {
		left, err := removeAside(dst)
		if len(left) == 0 {
			return nil
		}
		procs, listed, perr := processesUsing(left)
		if perr != nil {
			return perr
		}
		if listed == 0 {
			// A process that exits between the delete and the listing
			// leaves its copy free for one more pass.
			if unheld {
				return err
			}
			unheld = true
			continue
		}
		unheld = false
		for _, h := range procs {
			windows.WaitForSingleObject(h, windows.INFINITE)
			windows.CloseHandle(h)
		}
	}
}

var (
	rstrtmgr                = windows.NewLazySystemDLL("rstrtmgr.dll")
	procRmStartSession      = rstrtmgr.NewProc("RmStartSession")
	procRmEndSession        = rstrtmgr.NewProc("RmEndSession")
	procRmRegisterResources = rstrtmgr.NewProc("RmRegisterResources")
	procRmGetList           = rstrtmgr.NewProc("RmGetList")
)

// rmProcessInfo is RM_PROCESS_INFO.
type rmProcessInfo struct {
	ProcessID        uint32
	StartTime        windows.Filetime
	AppName          [256]uint16
	ServiceShortName [64]uint16
	ApplicationType  uint32
	AppStatus        uint32
	TSSessionID      uint32
	Restartable      int32
}

// processesUsing asks Restart Manager for the processes that hold any of
// paths open or loaded, and opens those still running for waiting on.
// listed counts the processes Restart Manager named.
func processesUsing(paths []string) (procs []windows.Handle, listed int, err error) {
	var session uint32
	var key [33]uint16
	if r, _, _ := procRmStartSession.Call(uintptr(unsafe.Pointer(&session)), 0, uintptr(unsafe.Pointer(&key[0]))); r != 0 {
		return nil, 0, fmt.Errorf("start Restart Manager session: %w", windows.Errno(r))
	}
	defer procRmEndSession.Call(uintptr(session))
	names := make([]*uint16, len(paths))
	for i, p := range paths {
		if names[i], err = windows.UTF16PtrFromString(p); err != nil {
			return nil, 0, err
		}
	}
	if r, _, _ := procRmRegisterResources.Call(uintptr(session), uintptr(len(names)), uintptr(unsafe.Pointer(&names[0])), 0, 0, 0, 0); r != 0 {
		return nil, 0, fmt.Errorf("register files with Restart Manager: %w", windows.Errno(r))
	}
	infos := make([]rmProcessInfo, 4)
	for {
		var needed, reasons uint32
		n := uint32(len(infos))
		r, _, _ := procRmGetList.Call(uintptr(session), uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&n)),
			uintptr(unsafe.Pointer(&infos[0])), uintptr(unsafe.Pointer(&reasons)))
		if r == uintptr(windows.ERROR_MORE_DATA) {
			infos = make([]rmProcessInfo, needed)
			continue
		}
		if r != 0 {
			return nil, 0, fmt.Errorf("list processes using %s: %w", strings.Join(paths, ", "), windows.Errno(r))
		}
		infos = infos[:n]
		break
	}
	for _, info := range infos {
		h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, info.ProcessID)
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			continue
		}
		var created, exited, kernel, user windows.Filetime
		if err == nil {
			if err = windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
				windows.CloseHandle(h)
			}
		}
		if err != nil {
			for _, h := range procs {
				windows.CloseHandle(h)
			}
			return nil, 0, fmt.Errorf("open process %d: %w", info.ProcessID, err)
		}
		// A process that has exited since may have passed its ID on.
		if created != info.StartTime {
			windows.CloseHandle(h)
			continue
		}
		procs = append(procs, h)
	}
	return procs, len(infos), nil
}

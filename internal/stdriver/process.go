package stdriver

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	processNameNative = 1 // PROCESS_NAME_NATIVE
	volumeNameNT      = 2 // VOLUME_NAME_NT
)

// ProcessInfo describes a running process.
type ProcessInfo struct {
	PID, ParentPID uint32
	ExeFile        string // image base name from the snapshot
	DevicePath     string // NT device path, empty if the process could not be opened
	DOSPath        string // Win32 path, empty if the process could not be opened
	created        uint64
}

// Processes lists running processes with their image paths.
func Processes() ([]ProcessInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("process snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var procs []ProcessInfo
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		p := ProcessInfo{
			PID:       entry.ProcessID,
			ParentPID: entry.ParentProcessID,
			ExeFile:   windows.UTF16ToString(entry.ExeFile[:]),
		}
		if h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID); err == nil {
			p.DevicePath, _ = imageName(h, processNameNative)
			p.DOSPath, _ = imageName(h, 0)
			var creation, exit, kernel, user windows.Filetime
			if windows.GetProcessTimes(h, &creation, &exit, &kernel, &user) == nil {
				p.created = uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
			}
			windows.CloseHandle(h)
		}
		procs = append(procs, p)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("walk process snapshot: %w", err)
	}

	// A parent PID refers to a recycled ID when that process started later
	// than its supposed child.
	byPID := make(map[uint32]*ProcessInfo, len(procs))
	for i := range procs {
		byPID[procs[i].PID] = &procs[i]
	}
	for i := range procs {
		if parent, ok := byPID[procs[i].ParentPID]; ok && parent.created > procs[i].created {
			procs[i].ParentPID = 0
		}
	}
	return procs, nil
}

func imageName(h windows.Handle, flags uint32) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, flags, &buf[0], &size); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:size]), nil
}

// registrationList converts a process listing for RegisterProcesses, which
// accepts processes without a known image path.
func registrationList(procs []ProcessInfo) []Process {
	out := make([]Process, 0, len(procs))
	for _, p := range procs {
		if p.PID == 0 {
			continue
		}
		out = append(out, Process{PID: p.PID, ParentPID: p.ParentPID, DevicePath: p.DevicePath})
	}
	return out
}

// RegisterRunningProcesses snapshots running processes and registers them.
func (d *Driver) RegisterRunningProcesses() error {
	procs, err := Processes()
	if err != nil {
		return err
	}
	return d.RegisterProcesses(registrationList(procs))
}

// DevicePath converts an absolute Win32 path to the NT device path the driver
// matches images against. Files that exist resolve through their handle,
// which also follows links; other paths resolve through the drive's device.
func DevicePath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path must be absolute: %s", path)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	h, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err == nil {
		defer windows.CloseHandle(h)
		buf := make([]uint16, windows.MAX_LONG_PATH)
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), volumeNameNT)
		if err == nil && int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}
	}

	vol := filepath.VolumeName(path)
	if len(vol) != 2 || vol[1] != ':' {
		return "", fmt.Errorf("cannot resolve device path of %s", path)
	}
	drive, err := windows.UTF16PtrFromString(vol)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_PATH)
	if _, err := windows.QueryDosDevice(drive, &buf[0], uint32(len(buf))); err != nil {
		return "", fmt.Errorf("resolve drive %s: %w", vol, err)
	}
	return windows.UTF16ToString(buf) + strings.TrimPrefix(path, vol), nil
}

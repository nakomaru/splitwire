// Package apps finds programs a user may want to route: the ones running
// now, the ones Explorer recorded as recently used, and the ones in the
// Start menu.
package apps

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"splitwire/internal/shortcut"
)

// Candidate is a program found on the system.
type Candidate struct {
	Path string
	// Name is the program's Start menu name, its file description, or its
	// file name.
	Name string
	// Running reports that the program runs now in this session, and
	// Window that it shows a window.
	Running, Window bool
	// LastUsed is when Explorer last started it, or zero.
	LastUsed time.Time
	// StartMenu reports that a Start menu shortcut starts it.
	StartMenu bool
}

// Find gathers the running, recently used and Start menu programs: the
// ones with a window first, then by most recent use, then the Start menu
// ones, then the ones running in the background, each by name.
func Find() []Candidate {
	found := make(map[string]*Candidate)
	add := func(c Candidate) {
		k := strings.ToLower(c.Path)
		have := found[k]
		if have == nil {
			c := c
			found[k] = &c
			return
		}
		have.Running = have.Running || c.Running
		have.Window = have.Window || c.Window
		have.StartMenu = have.StartMenu || c.StartMenu
		if c.LastUsed.After(have.LastUsed) {
			have.LastUsed = c.LastUsed
		}
		if c.StartMenu && c.Name != "" {
			have.Name = c.Name
		}
	}
	for _, c := range StartMenu() {
		add(c)
	}
	for _, c := range Recent() {
		add(c)
	}
	for _, c := range Running() {
		add(c)
	}
	all := make([]Candidate, 0, len(found))
	for _, c := range found {
		if c.Name == "" {
			c.Name = DisplayName(c.Path)
		}
		all = append(all, *c)
	}
	tier := func(c Candidate) int {
		switch {
		case c.Window:
			return 0
		case !c.LastUsed.IsZero():
			return 1
		case c.StartMenu:
			return 2
		}
		return 3
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if ta, tb := tier(a), tier(b); ta != tb {
			return ta < tb
		}
		if !a.LastUsed.Equal(b.LastUsed) {
			return a.LastUsed.After(b.LastUsed)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return all
}

var (
	user32                    = windows.NewLazySystemDLL("user32.dll")
	procGetWindow             = user32.NewProc("GetWindow")
	procGetWindowTextLengthW  = user32.NewProc("GetWindowTextLengthW")
	procDwmGetWindowAttribute = windows.NewLazySystemDLL("dwmapi.dll").NewProc("DwmGetWindowAttribute")
	enumWindowsProc           = windows.NewCallback(collectWindow)
	windowPIDs                map[uint32]bool
)

// collectWindow records the process of a top-level window that shows in
// the taskbar: visible, unowned, titled and not cloaked.
func collectWindow(hwnd windows.HWND, _ uintptr) uintptr {
	const gwOwner = 4
	const dwmwaCloaked = 14
	owner, _, _ := procGetWindow.Call(uintptr(hwnd), gwOwner)
	title, _, _ := procGetWindowTextLengthW.Call(uintptr(hwnd))
	var cloaked uint32
	procDwmGetWindowAttribute.Call(uintptr(hwnd), dwmwaCloaked, uintptr(unsafe.Pointer(&cloaked)), 4)
	if windows.IsWindowVisible(hwnd) && owner == 0 && title > 0 && cloaked == 0 {
		var pid uint32
		windows.GetWindowThreadProcessId(hwnd, &pid)
		windowPIDs[pid] = true
	}
	return 1
}

// Running lists the programs running in this session, leaving out the
// Windows folder's background processes: a program there counts only with
// a window.
func Running() []Candidate {
	windowPIDs = make(map[uint32]bool)
	windows.EnumWindows(enumWindowsProc, nil)
	withWindow := windowPIDs
	windowPIDs = nil

	var session uint32
	windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session)
	self, _ := os.Executable()
	sysRoot := strings.ToLower(os.Getenv("SystemRoot")) + `\`

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var out []Candidate
	seen := make(map[string]bool)
	e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err := windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		var s uint32
		if windows.ProcessIdToSessionId(e.ProcessID, &s) != nil || s != session {
			continue
		}
		path := imagePath(e.ProcessID)
		k := strings.ToLower(path)
		if path == "" || seen[k] || strings.EqualFold(path, self) {
			continue
		}
		if strings.HasPrefix(k, sysRoot) && !withWindow[e.ProcessID] {
			continue
		}
		seen[k] = true
		out = append(out, Candidate{Path: path, Running: true, Window: withWindow[e.ProcessID]})
	}
	return out
}

func imagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	var buf [windows.MAX_LONG_PATH]uint16
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// userAssist holds Explorer's record of started programs, with ROT13
// encoded names.
const userAssist = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`

// Recent lists the programs Explorer recorded as started, with when.
// Explorer records them only while "Track app launches" is on.
func Recent() []Candidate {
	root, err := registry.OpenKey(registry.CURRENT_USER, userAssist, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer root.Close()
	guids, _ := root.ReadSubKeyNames(-1)
	var out []Candidate
	for _, g := range guids {
		k, err := registry.OpenKey(root, g+`\Count`, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := k.ReadValueNames(-1)
		for _, n := range names {
			path := expandKnownFolder(rot13(n))
			if !strings.EqualFold(filepath.Ext(path), ".exe") || !exists(path) {
				continue
			}
			data, _, err := k.GetBinaryValue(n)
			if err != nil {
				continue
			}
			out = append(out, Candidate{Path: path, LastUsed: lastRun(data)})
		}
		k.Close()
	}
	return out
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

// expandKnownFolder replaces a leading {known folder ID} with its path.
func expandKnownFolder(p string) string {
	if !strings.HasPrefix(p, "{") {
		return p
	}
	id, rest, ok := strings.Cut(p, `}\`)
	if !ok {
		return p
	}
	g, err := windows.GUIDFromString(id + "}")
	if err != nil {
		return p
	}
	dir, err := windows.KnownFolderPath((*windows.KNOWNFOLDERID)(&g), 0)
	if err != nil {
		return p
	}
	return filepath.Join(dir, rest)
}

// lastRun reads the last start time of a UserAssist entry: a FILETIME at
// offset 60 of the 72-byte record.
func lastRun(data []byte) time.Time {
	if len(data) < 68 {
		return time.Time{}
	}
	ft := windows.Filetime{
		LowDateTime:  binary.LittleEndian.Uint32(data[60:]),
		HighDateTime: binary.LittleEndian.Uint32(data[64:]),
	}
	if ft.HighDateTime == 0 && ft.LowDateTime == 0 {
		return time.Time{}
	}
	return time.Unix(0, ft.Nanoseconds())
}

// StartMenu lists the programs the current user's and the shared Start
// menu shortcuts start, named after the shortcuts, leaving out
// uninstallers.
func StartMenu() []Candidate {
	rd, err := shortcut.NewReader()
	if err != nil {
		return nil
	}
	defer rd.Close()
	var out []Candidate
	for _, folder := range []*windows.KNOWNFOLDERID{windows.FOLDERID_Programs, windows.FOLDERID_CommonPrograms} {
		dir, err := windows.KnownFolderPath(folder, 0)
		if err != nil {
			continue
		}
		filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.EqualFold(filepath.Ext(p), ".lnk") {
				return nil
			}
			name := strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
			if uninstaller(name) {
				return nil
			}
			target := rd.Target(p)
			if !strings.EqualFold(filepath.Ext(target), ".exe") || uninstaller(filepath.Base(target)) || !exists(target) {
				return nil
			}
			out = append(out, Candidate{Path: target, Name: name, StartMenu: true})
			return nil
		})
	}
	return out
}

func uninstaller(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "uninstall") || strings.HasPrefix(n, "unins")
}

func exists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// DisplayName is the program's file description, or its file name without
// the extension.
func DisplayName(path string) string {
	if d := fileDescription(path); d != "" {
		return d
	}
	return strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
}

func fileDescription(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return ""
	}
	info := make([]byte, size)
	if windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&info[0])) != nil {
		return ""
	}
	var trans unsafe.Pointer
	var n uint32
	if windows.VerQueryValue(unsafe.Pointer(&info[0]), `\VarFileInfo\Translation`, unsafe.Pointer(&trans), &n) != nil || n < 4 {
		return ""
	}
	t := (*[2]uint16)(trans)
	var desc unsafe.Pointer
	key := `\StringFileInfo\` + hex4(t[0]) + hex4(t[1]) + `\FileDescription`
	if windows.VerQueryValue(unsafe.Pointer(&info[0]), key, unsafe.Pointer(&desc), &n) != nil || n == 0 {
		return ""
	}
	return strings.TrimSpace(windows.UTF16PtrToString((*uint16)(desc)))
}

func hex4(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>12], digits[v>>8&0xf], digits[v>>4&0xf], digits[v&0xf]})
}

// versionDir matches a folder named for a version, optionally after a
// prefix such as "app-".
var versionDir = regexp.MustCompile(`^(\D*?)v?\d+(\.\d+)+$`)

// Pattern is the App entry for path: folders named for a version become *
// so the entry keeps matching after the program updates.
func Pattern(path string) string {
	parts := strings.Split(filepath.Clean(path), `\`)
	for i := 1; i < len(parts)-1; i++ {
		if m := versionDir.FindStringSubmatch(parts[i]); m != nil {
			parts[i] = m[1] + "*"
		}
	}
	return strings.Join(parts, `\`)
}

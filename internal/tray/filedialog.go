package tray

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetOpenFileNameW = windows.NewLazySystemDLL("comdlg32.dll").NewProc("GetOpenFileNameW")

// openFile shows the Open dialog, owned by owner, for one existing file.
// filter pairs descriptions with patterns, such as "Programs", "*.exe".
func openFile(owner uintptr, title string, filter ...string) (string, bool) {
	f, _ := windows.UTF16FromString(strings.Join(filter, "\x00") + "\x00")
	t, _ := windows.UTF16PtrFromString(title)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	const ofnFileMustExist, ofnPathMustExist, ofnHideReadOnly, ofnExplorer, ofnNoChangeDir = 0x1000, 0x800, 0x4, 0x80000, 0x8
	ofn := struct {
		size                       uint32
		owner, instance            uintptr
		filter, customFilter       *uint16
		maxCustomFilter, filterIdx uint32
		file                       *uint16
		maxFile                    uint32
		fileTitle                  *uint16
		maxFileTitle               uint32
		initialDir, title          *uint16
		flags                      uint32
		fileOffset, fileExtension  uint16
		defExt                     *uint16
		custData, hook             uintptr
		templateName               *uint16
		reserved                   uintptr
		reserved2, flagsEx         uint32
	}{owner: owner, filter: &f[0], filterIdx: 1, file: &buf[0], maxFile: uint32(len(buf)), title: t,
		flags: ofnFileMustExist | ofnPathMustExist | ofnHideReadOnly | ofnExplorer | ofnNoChangeDir}
	ofn.size = uint32(unsafe.Sizeof(ofn))
	r, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return "", false
	}
	return windows.UTF16ToString(buf), true
}

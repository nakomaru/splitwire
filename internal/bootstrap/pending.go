package bootstrap

import (
	"errors"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	sessionManagerKey = `SYSTEM\CurrentControlSet\Control\Session Manager`
	pendingValue      = "PendingFileRenameOperations"
)

var procRegSetValueExW = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegSetValueExW")

// pendingPath strips the prefixes Windows stores before a path in
// PendingFileRenameOperations: an optional *<digits> flag and \??\.
func pendingPath(entry string) string {
	if strings.HasPrefix(entry, "*") {
		i := 1
		for i < len(entry) && entry[i] >= '0' && entry[i] <= '9' {
			i++
		}
		entry = entry[i:]
	}
	return strings.TrimPrefix(entry, `\??\`)
}

// filterPending removes the deletions of paths under root from the
// PendingFileRenameOperations data: pairs of NUL-terminated source and
// destination strings, an empty destination meaning delete, and a final
// NUL. It reports how many it removed.
func filterPending(data []uint16, root string) ([]uint16, int) {
	var out []uint16
	removed := 0
	prefix := strings.ToLower(strings.TrimRight(root, `\`))
	read := func(i int) (string, int) {
		j := i
		for j < len(data) && data[j] != 0 {
			j++
		}
		return string(utf16.Decode(data[i:j])), j + 1
	}
	for i := 0; i < len(data); {
		src, next := read(i)
		if src == "" {
			break
		}
		dst, after := read(next)
		p := strings.ToLower(pendingPath(src))
		if dst == "" && (p == prefix || strings.HasPrefix(p, prefix+`\`)) {
			removed++
		} else {
			out = append(out, data[i:after]...)
		}
		i = after
	}
	return append(out, 0), removed
}

// CancelPendingDeletes cancels the deletions an uninstall scheduled for the
// next restart under the install root, so a new install survives it. It
// reports how many it canceled.
func CancelPendingDeletes() (int, error) {
	root, err := Root()
	if err != nil {
		return 0, err
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, sessionManagerKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return 0, err
	}
	defer k.Close()
	n, typ, err := k.GetValue(pendingValue, nil)
	if errors.Is(err, registry.ErrNotExist) {
		return 0, nil
	}
	if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
		return 0, err
	}
	if typ != registry.MULTI_SZ || n < 2 {
		return 0, nil
	}
	buf := make([]byte, n)
	if _, _, err := k.GetValue(pendingValue, buf); err != nil {
		return 0, err
	}
	data := unsafe.Slice((*uint16)(unsafe.Pointer(&buf[0])), n/2)
	kept, removed := filterPending(data, root)
	if removed == 0 {
		return 0, nil
	}
	if len(kept) <= 1 {
		return removed, k.DeleteValue(pendingValue)
	}
	name, _ := windows.UTF16PtrFromString(pendingValue)
	r, _, _ := procRegSetValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(name)), 0, registry.MULTI_SZ,
		uintptr(unsafe.Pointer(&kept[0])), uintptr(len(kept)*2))
	if r != 0 {
		return 0, windows.Errno(r)
	}
	return removed, nil
}

package shortcut

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	slotGetPath = 3
	slotLoad    = 5
)

// Reader reads shortcut targets on one thread, which it keeps for COM until
// Close.
type Reader struct {
	link, file *comObject
}

// NewReader prepares to read shortcuts. The calling goroutine stays on its
// thread until Close.
func NewReader() (*Reader, error) {
	runtime.LockOSThread()
	if r, _, _ := procCoInitializeEx.Call(0, coinitApartment); int32(r) < 0 {
		runtime.UnlockOSThread()
		return nil, windows.Errno(r)
	}
	rd := &Reader{}
	r, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidShellLink)), 0, clsctxInproc,
		uintptr(unsafe.Pointer(&iidShellLinkW)), uintptr(unsafe.Pointer(&rd.link)))
	if int32(r) < 0 {
		rd.Close()
		return nil, windows.Errno(r)
	}
	if err := call(rd.link, slotQueryInterface, uintptr(unsafe.Pointer(&iidPersistFile)), uintptr(unsafe.Pointer(&rd.file))); err != nil {
		rd.Close()
		return nil, err
	}
	return rd, nil
}

// Target is the file a shortcut points to, or "" for a shortcut to
// something other than a file.
func (rd *Reader) Target(path string) string {
	p := utf16(path)
	const stgmRead = 0
	if call(rd.file, slotLoad, uintptr(unsafe.Pointer(p)), stgmRead) != nil {
		return ""
	}
	runtime.KeepAlive(p)
	var buf [windows.MAX_PATH]uint16
	if call(rd.link, slotGetPath, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0) != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}

// Close releases the reader and its thread.
func (rd *Reader) Close() {
	if rd.file != nil {
		call(rd.file, slotRelease)
	}
	if rd.link != nil {
		call(rd.link, slotRelease)
	}
	procCoUninitialize.Call()
	runtime.UnlockOSThread()
}

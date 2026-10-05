// Package shortcut writes Windows shell links (.lnk files) through the
// IShellLinkW and IPersistFile COM interfaces.
package shortcut

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ole32                = windows.NewLazySystemDLL("ole32.dll")
	procCoInitializeEx   = ole32.NewProc("CoInitializeEx")
	procCoUninitialize   = ole32.NewProc("CoUninitialize")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")

	clsidShellLink  = windows.GUID{Data1: 0x00021401, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidShellLinkW   = windows.GUID{Data1: 0x000214f9, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	iidPersistFile  = windows.GUID{Data1: 0x0000010b, Data4: [8]byte{0xc0, 0, 0, 0, 0, 0, 0, 0x46}}
	coinitApartment = uintptr(0x2)
	clsctxInproc    = uintptr(0x1)
)

// Vtable slots of the interfaces, after IUnknown's QueryInterface (0),
// AddRef (1) and Release (2).
const (
	slotQueryInterface = 0
	slotRelease        = 2

	slotSetDescription  = 7
	slotSetArguments    = 11
	slotSetIconLocation = 17
	slotSetPath         = 20

	slotSave = 6
)

type comObject struct{ vtbl *[32]uintptr }

func call(obj *comObject, slot int, args ...uintptr) error {
	r, _, _ := syscall.SyscallN(obj.vtbl[slot], append([]uintptr{uintptr(unsafe.Pointer(obj))}, args...)...)
	if int32(r) < 0 {
		return fmt.Errorf("COM error %#x", uint32(r))
	}
	return nil
}

func utf16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

// Create writes a shortcut at path that starts target with args, showing
// target's own icon.
func Create(path, target, args, description string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, _ := procCoInitializeEx.Call(0, coinitApartment); int32(r) < 0 {
		return fmt.Errorf("CoInitializeEx: %#x", uint32(r))
	}
	defer procCoUninitialize.Call()

	var link *comObject
	r, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidShellLink)), 0, clsctxInproc,
		uintptr(unsafe.Pointer(&iidShellLinkW)), uintptr(unsafe.Pointer(&link)))
	if int32(r) < 0 {
		return fmt.Errorf("create shell link: %#x", uint32(r))
	}
	defer call(link, slotRelease)
	// The strings stay referenced until the end of Create, so the
	// collector keeps them while COM reads them.
	pTarget, pArgs, pDesc, pPath := utf16(target), utf16(args), utf16(description), utf16(path)
	defer runtime.KeepAlive([]*uint16{pTarget, pArgs, pDesc, pPath})
	for _, step := range []struct {
		slot int
		args []uintptr
	}{
		{slotSetPath, []uintptr{uintptr(unsafe.Pointer(pTarget))}},
		{slotSetArguments, []uintptr{uintptr(unsafe.Pointer(pArgs))}},
		{slotSetDescription, []uintptr{uintptr(unsafe.Pointer(pDesc))}},
		{slotSetIconLocation, []uintptr{uintptr(unsafe.Pointer(pTarget)), 0}},
	} {
		if err := call(link, step.slot, step.args...); err != nil {
			return err
		}
	}
	var file *comObject
	if err := call(link, slotQueryInterface, uintptr(unsafe.Pointer(&iidPersistFile)), uintptr(unsafe.Pointer(&file))); err != nil {
		return err
	}
	defer call(file, slotRelease)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return call(file, slotSave, uintptr(unsafe.Pointer(pPath)), 1)
}

// StartMenu is the shortcut's path in the Start menu of every user.
func StartMenu(name string) (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_CommonPrograms, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".lnk"), nil
}

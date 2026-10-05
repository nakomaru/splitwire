package tray

import (
	"fmt"
	"runtime"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                      = windows.NewLazySystemDLL("user32.dll")
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	procDialogBoxIndirectParamW = user32.NewProc("DialogBoxIndirectParamW")
	procEndDialog               = user32.NewProc("EndDialog")
	procSetDlgItemTextW         = user32.NewProc("SetDlgItemTextW")
	procGetDlgItemTextW         = user32.NewProc("GetDlgItemTextW")
	procSendDlgItemMessageW     = user32.NewProc("SendDlgItemMessageW")
	procOpenClipboard           = user32.NewProc("OpenClipboard")
	procEmptyClipboard          = user32.NewProc("EmptyClipboard")
	procSetClipboardData        = user32.NewProc("SetClipboardData")
	procCloseClipboard          = user32.NewProc("CloseClipboard")
	procGlobalAlloc             = kernel32.NewProc("GlobalAlloc")
	procGlobalLock              = kernel32.NewProc("GlobalLock")
	procGlobalUnlock            = kernel32.NewProc("GlobalUnlock")
	procGlobalFree              = kernel32.NewProc("GlobalFree")
	procRtlMoveMemory           = kernel32.NewProc("RtlMoveMemory")
)

const (
	wmInitDialog = 0x0110
	wmCommand    = 0x0111
	emLimitText  = 0x00C5
	idOK         = 1
	idCancel     = 2
	idEdit       = 100

	dsSetFont       = 0x40
	dsModalFrame    = 0x80
	dsSetForeground = 0x200
	dsCenter        = 0x800
	wsPopup         = 0x80000000
	wsCaption       = 0x00C00000
	wsSysMenu       = 0x00080000
	wsChild         = 0x40000000
	wsVisible       = 0x10000000
	wsBorder        = 0x00800000
	wsTabStop       = 0x00010000
	esAutoHScroll   = 0x0080
	esNumber        = 0x2000
	bsDefPushButton = 0x0001

	classButton = 0x0080
	classEdit   = 0x0081
	classStatic = 0x0082
)

// dlgTemplate builds an in-memory DLGTEMPLATE: 16-bit words, with each
// control starting on a 32-bit boundary.
type dlgTemplate struct{ w []uint16 }

func (t *dlgTemplate) dword(v uint32) { t.w = append(t.w, uint16(v), uint16(v>>16)) }
func (t *dlgTemplate) word(v uint16)  { t.w = append(t.w, v) }
func (t *dlgTemplate) str(s string) {
	u, _ := windows.UTF16FromString(s)
	t.w = append(t.w, u...)
}
func (t *dlgTemplate) align() {
	if len(t.w)%2 == 1 {
		t.w = append(t.w, 0)
	}
}

func (t *dlgTemplate) control(class uint16, id uint16, style uint32, x, y, cx, cy int16, text string) {
	t.align()
	t.dword(style | wsChild | wsVisible)
	t.dword(0)
	for _, v := range []int16{x, y, cx, cy} {
		t.word(uint16(v))
	}
	t.word(id)
	t.word(0xffff)
	t.word(class)
	t.str(text)
	t.word(0) // no creation data
}

// dialog state for the one open dialog; dialogs run one at a time.
var (
	dialogMu       sync.Mutex
	dialogProc     = windows.NewCallback(portDialogProc)
	dialogInitial  string
	dialogValidate func(uint16) error
	dialogResult   uint16
)

// askPort shows a dialog for a port number. validate rejects an entry
// with an error, which the dialog shows while it stays open. It reports
// false when canceled.
func askPort(title, prompt string, current uint16, validate func(uint16) error) (uint16, bool) {
	dialogMu.Lock()
	defer dialogMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	t := &dlgTemplate{}
	t.dword(wsPopup | wsCaption | wsSysMenu | dsModalFrame | dsSetFont | dsCenter | dsSetForeground)
	t.dword(0)
	t.word(4) // controls
	for _, v := range []int16{0, 0, 212, 74} {
		t.word(uint16(v))
	}
	t.word(0) // no menu
	t.word(0) // default class
	t.str(title)
	t.word(9)
	t.str("Segoe UI")
	t.control(classStatic, 0xffff, 0, 7, 7, 198, 26, prompt)
	t.control(classEdit, idEdit, wsBorder|wsTabStop|esNumber|esAutoHScroll, 7, 34, 60, 14, "")
	t.control(classButton, idOK, wsTabStop|bsDefPushButton, 101, 54, 50, 14, "OK")
	t.control(classButton, idCancel, wsTabStop, 155, 54, 50, 14, "Cancel")

	dialogInitial = ""
	if current != 0 {
		dialogInitial = strconv.Itoa(int(current))
	}
	dialogValidate = validate
	var instance windows.Handle
	windows.GetModuleHandleEx(0, nil, &instance)
	r, _, _ := procDialogBoxIndirectParamW.Call(uintptr(instance), uintptr(unsafe.Pointer(&t.w[0])), 0, dialogProc, 0)
	runtime.KeepAlive(t)
	return dialogResult, r == idOK
}

func portDialogProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case wmInitDialog:
		text, _ := windows.UTF16PtrFromString(dialogInitial)
		procSetDlgItemTextW.Call(hwnd, idEdit, uintptr(unsafe.Pointer(text)))
		procSendDlgItemMessageW.Call(hwnd, idEdit, emLimitText, 5, 0)
		return 1
	case wmCommand:
		switch wparam & 0xffff {
		case idOK:
			var buf [8]uint16
			procGetDlgItemTextW.Call(hwnd, idEdit, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
			port, err := strconv.ParseUint(windows.UTF16ToString(buf[:]), 10, 16)
			if err != nil || port == 0 {
				err = fmt.Errorf("enter a port from 1 to 65535")
			} else {
				err = dialogValidate(uint16(port))
			}
			if err != nil {
				text, _ := windows.UTF16PtrFromString(err.Error())
				caption, _ := windows.UTF16PtrFromString("splitwire")
				windows.MessageBox(windows.HWND(hwnd), text, caption, windows.MB_OK|windows.MB_ICONWARNING)
				return 1
			}
			dialogResult = uint16(port)
			procEndDialog.Call(hwnd, idOK)
			return 1
		case idCancel:
			procEndDialog.Call(hwnd, idCancel)
			return 1
		}
	}
	return 0
}

// copyText puts text on the clipboard.
func copyText(text string) error {
	u, err := windows.UTF16FromString(text)
	if err != nil {
		return err
	}
	if r, _, err := procOpenClipboard.Call(0); r == 0 {
		return err
	}
	defer procCloseClipboard.Call()
	procEmptyClipboard.Call()
	const gmemMoveable = 0x0002
	const cfUnicodeText = 13
	size := uintptr(len(u) * 2)
	h, _, err := procGlobalAlloc.Call(gmemMoveable, size)
	if h == 0 {
		return err
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return err
	}
	procRtlMoveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), size)
	procGlobalUnlock.Call(h)
	if r, _, err := procSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		procGlobalFree.Call(h)
		return err
	}
	return nil
}

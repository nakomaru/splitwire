package tray

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var procInitCommonControlsEx = windows.NewLazySystemDLL("comctl32.dll").NewProc("InitCommonControlsEx")

const (
	ttmSetDelayTime    = 0x0403
	ttmSetMaxTipWidth  = 0x0418
	ttmAddToolW        = 0x0432
	ttmNewToolRectW    = 0x0434
	ttmUpdateTipTextW  = 0x0439
	ttfIDIsHwnd        = 0x0001
	ttfSubclass        = 0x0010
	ttsAlwaysTip       = 0x01
	ttsNoPrefix        = 0x02
	ttdtAutoPop        = 2
	wsExTopmost        = 0x00000008
	iccWin95Classes    = 0x000000FF
	tipAutoPopMillisec = 30000
)

// toolInfo is TTTOOLINFOW.
type toolInfo struct {
	size, flags uint32
	hwnd, id    uintptr
	r           rect
	instance    uintptr
	text        *uint16
	lparam      uintptr
	reserved    uintptr
}

// tipWindow is the form's tooltip control, created on first use.
func (f *form) tipWindow() uintptr {
	if f.tips != 0 {
		return f.tips
	}
	icc := struct{ size, classes uint32 }{8, iccWin95Classes}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))
	class, _ := windows.UTF16PtrFromString("tooltips_class32")
	f.tips, _, _ = procCreateWindowExW.Call(wsExTopmost, uintptr(unsafe.Pointer(class)), 0, wsPopup|ttsAlwaysTip|ttsNoPrefix,
		0, 0, 0, 0, f.hwnd, 0, uintptr(appInstance), 0)
	procSendMessageW.Call(f.tips, ttmSetDelayTime, ttdtAutoPop, tipAutoPopMillisec)
	f.themeTips()
	return f.tips
}

func (f *form) themeTips() {
	if f.tips == 0 {
		return
	}
	procSendMessageW.Call(f.tips, ttmSetMaxTipWidth, 0, uintptr(f.px(360)))
	if f.col.dark {
		name, _ := windows.UTF16PtrFromString("DarkMode_Explorer")
		procSetWindowTheme.Call(f.tips, uintptr(unsafe.Pointer(name)), 0)
	} else {
		procSetWindowTheme.Call(f.tips, 0, 0)
	}
}

// tools are the tooltip's entries for a control: one for its window, which
// shows while it is enabled, and one for its place on the form, which
// shows for labels and disabled controls, whose mouse input goes to the
// form.
func (f *form) tools(c *control) []toolInfo {
	place := toolInfo{flags: ttfSubclass, hwnd: f.hwnd, id: uintptr(c.id)}
	if !c.hidden {
		place.r = c.r
	}
	out := []toolInfo{place}
	if c.hwnd != 0 {
		out = append(out, toolInfo{flags: ttfIDIsHwnd | ttfSubclass, hwnd: f.hwnd, id: c.hwnd})
	}
	for i := range out {
		out[i].size = uint32(unsafe.Sizeof(out[i]))
	}
	return out
}

// setTip sets the tooltip of a control.
func (f *form) setTip(c *control, text string) {
	tips := f.tipWindow()
	added := c.tipped
	c.tip, c.tipped = text, true
	u, _ := windows.UTF16PtrFromString(text)
	for _, t := range f.tools(c) {
		t.text = u
		msg := uintptr(ttmUpdateTipTextW)
		if !added {
			msg = ttmAddToolW
		}
		procSendMessageW.Call(tips, msg, 0, uintptr(unsafe.Pointer(&t)))
	}
}

// moveTip keeps the tooltip of a control on its place, or off the form
// while the control is hidden.
func (f *form) moveTip(c *control) {
	if !c.tipped {
		return
	}
	t := f.tools(c)[0]
	procSendMessageW.Call(f.tips, ttmNewToolRectW, 0, uintptr(unsafe.Pointer(&t)))
}

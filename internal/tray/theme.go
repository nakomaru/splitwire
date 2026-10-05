package tray

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// personalizeKey holds AppsUseLightTheme, 0 when apps use dark mode.
const personalizeKey = `Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`

var (
	dwmapi                    = windows.NewLazySystemDLL("dwmapi.dll")
	uxthemeDLL                = windows.NewLazySystemDLL("uxtheme.dll")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
	procSetWindowTheme        = uxthemeDLL.NewProc("SetWindowTheme")
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	procCreateSolidBrush      = gdi32.NewProc("CreateSolidBrush")
	procDeleteObject          = gdi32.NewProc("DeleteObject")
	procSetBkColor            = gdi32.NewProc("SetBkColor")
	procFillRect              = user32.NewProc("FillRect")
)

// uxtheme exports these only by ordinal, from Windows 10 1903 on; Explorer
// and the shell use them for dark menus.
const (
	ordRefreshColorPolicy     = 104
	ordAllowDarkModeForWindow = 133
	ordSetPreferredAppMode    = 135
	ordFlushMenuThemes        = 136
	appModeAllowDark          = 1
	wmThemeChanged            = 0x031A
)

const dwmwaUseImmersiveDarkMode = 20

// testTheme makes darkMode report dark (1) or light (2) in tests; 0
// follows the system.
var testTheme int

// darkMode reports whether apps use dark mode.
func darkMode() bool {
	if testTheme != 0 {
		return testTheme == 1
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, personalizeKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	return err == nil && v == 0
}

func highContrast() bool {
	const spiGetHighContrast = 0x0042
	const hcfHighContrastOn = 0x1
	var hc struct {
		size, flags uint32
		scheme      *uint16
	}
	hc.size = uint32(unsafe.Sizeof(hc))
	procSystemParametersInfoW.Call(spiGetHighContrast, uintptr(hc.size), uintptr(unsafe.Pointer(&hc)), 0)
	return hc.flags&hcfHighContrastOn != 0
}

// uxthemeOrdinal finds an uxtheme function exported only by ordinal.
func uxthemeOrdinal(ordinal uintptr) uintptr {
	if uxthemeDLL.Load() != nil {
		return 0
	}
	p, err := windows.GetProcAddressByOrdinal(windows.Handle(uxthemeDLL.Handle()), ordinal)
	if err != nil {
		return 0
	}
	return p
}

// followSystemTheme lets this process's menus follow the system's dark
// mode, and refreshes them whenever the setting changes.
func followSystemTheme() {
	setMode, flush := uxthemeOrdinal(ordSetPreferredAppMode), uxthemeOrdinal(ordFlushMenuThemes)
	if setMode == 0 || flush == 0 {
		return
	}
	syscallN(setMode, appModeAllowDark)
	if refresh := uxthemeOrdinal(ordRefreshColorPolicy); refresh != 0 {
		syscallN(refresh)
	}
	syscallN(flush)
	go func() {
		k, err := registry.OpenKey(registry.CURRENT_USER, personalizeKey, registry.NOTIFY)
		if err != nil {
			return
		}
		defer k.Close()
		for {
			if windows.RegNotifyChangeKeyValue(windows.Handle(k), false, windows.REG_NOTIFY_CHANGE_LAST_SET, 0, false) != nil {
				return
			}
			syscallN(flush)
		}
	}()
}

// palette holds a dialog's colors as COLORREF values (0x00BBGGRR).
type palette struct {
	dark                           bool
	content, footer, text, subtext uint32
	edit                           uint32
}

func rgb(r, g, b uint8) uint32 { return uint32(r) | uint32(g)<<8 | uint32(b)<<16 }

// currentPalette follows the Windows 11 dialog look: a content area above
// a footer that holds the buttons, in dark or light colors. High contrast
// themes use the system colors.
func currentPalette() palette {
	if highContrast() {
		sys := func(i uintptr) uint32 { c, _, _ := procGetSysColor.Call(i); return uint32(c) }
		const colorWindow, colorWindowText, colorBtnFace, colorGrayText = 5, 8, 15, 17
		return palette{content: sys(colorWindow), footer: sys(colorBtnFace), text: sys(colorWindowText),
			subtext: sys(colorGrayText), edit: sys(colorWindow)}
	}
	if darkMode() {
		return palette{dark: true, content: rgb(0x2b, 0x2b, 0x2b), footer: rgb(0x20, 0x20, 0x20),
			text: rgb(0xff, 0xff, 0xff), subtext: rgb(0xab, 0xab, 0xab), edit: rgb(0x1f, 0x1f, 0x1f)}
	}
	return palette{content: rgb(0xff, 0xff, 0xff), footer: rgb(0xf3, 0xf3, 0xf3),
		text: rgb(0x1a, 0x1a, 0x1a), subtext: rgb(0x5d, 0x5d, 0x5d), edit: rgb(0xff, 0xff, 0xff)}
}

// brushes are a dialog's solid brushes for its palette.
type brushes struct{ content, footer, edit uintptr }

func newBrushes(p palette) brushes {
	mk := func(c uint32) uintptr { b, _, _ := procCreateSolidBrush.Call(uintptr(c)); return b }
	return brushes{mk(p.content), mk(p.footer), mk(p.edit)}
}

func (b brushes) free() {
	for _, h := range []uintptr{b.content, b.footer, b.edit} {
		procDeleteObject.Call(h)
	}
}

// themeWindow gives a dialog a dark title bar in dark mode.
func themeWindow(hwnd uintptr, p palette) {
	on := int32(0)
	if p.dark {
		on = 1
	}
	procDwmSetWindowAttribute.Call(hwnd, dwmwaUseImmersiveDarkMode, uintptr(unsafe.Pointer(&on)), 4)
}

// themeControl applies a visual style for a control class: "Explorer"
// for buttons and checkboxes, "CFD" for edits. In dark mode the control
// opts in to dark drawing first, which makes Windows use the style's dark
// variant.
func themeControl(ctrl uintptr, p palette, class string) {
	if p.dark {
		if allow := uxthemeOrdinal(ordAllowDarkModeForWindow); allow != 0 {
			syscallN(allow, ctrl, 1)
		}
	}
	name, _ := windows.UTF16PtrFromString(class)
	procSetWindowTheme.Call(ctrl, uintptr(unsafe.Pointer(name)), 0)
	procSendMessageW.Call(ctrl, wmThemeChanged, 0, 0)
}

func syscallN(fn uintptr, args ...uintptr) uintptr {
	r, _, _ := syscall.SyscallN(fn, args...)
	return r
}

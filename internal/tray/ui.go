package tray

import (
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A small toolkit for the app's resizable windows: owner-drawn buttons,
// checkboxes, radio buttons, tabs and lists in the Windows 11 style, edit
// boxes in painted fields, and labels painted by the window. It follows
// dark mode and the window's DPI.

var (
	procRegisterClassExW         = user32.NewProc("RegisterClassExW")
	procCreateWindowExW          = user32.NewProc("CreateWindowExW")
	procDefWindowProcW           = user32.NewProc("DefWindowProcW")
	procDestroyWindow            = user32.NewProc("DestroyWindow")
	procShowWindow               = user32.NewProc("ShowWindow")
	procGetMessageW              = user32.NewProc("GetMessageW")
	procTranslateMessage         = user32.NewProc("TranslateMessage")
	procDispatchMessageW         = user32.NewProc("DispatchMessageW")
	procIsDialogMessageW         = user32.NewProc("IsDialogMessageW")
	procPostMessageW             = user32.NewProc("PostMessageW")
	procPostQuitMessage          = user32.NewProc("PostQuitMessage")
	procBeginPaint               = user32.NewProc("BeginPaint")
	procEndPaint                 = user32.NewProc("EndPaint")
	procInvalidateRect           = user32.NewProc("InvalidateRect")
	procSetWindowTextW           = user32.NewProc("SetWindowTextW")
	procGetWindowTextLengthW     = user32.NewProc("GetWindowTextLengthW")
	procGetDpiForWindow          = user32.NewProc("GetDpiForWindow")
	procLoadCursorW              = user32.NewProc("LoadCursorW")
	procLoadImageW               = user32.NewProc("LoadImageW")
	procSetFocus                 = user32.NewProc("SetFocus")
	procGetFocus                 = user32.NewProc("GetFocus")
	procTrackPopupMenuEx         = user32.NewProc("TrackPopupMenuEx")
	procCreatePopupMenu          = user32.NewProc("CreatePopupMenu")
	procAppendMenuW              = user32.NewProc("AppendMenuW")
	procDestroyMenu              = user32.NewProc("DestroyMenu")
	procGetCursorPos             = user32.NewProc("GetCursorPos")
	procClientToScreen           = user32.NewProc("ClientToScreen")
	procScreenToClient           = user32.NewProc("ScreenToClient")
	procSystemParametersInfoDpi  = user32.NewProc("SystemParametersInfoForDpi")
	procAdjustWindowRectExForDpi = user32.NewProc("AdjustWindowRectExForDpi")
	procGetAncestor              = user32.NewProc("GetAncestor")
	procMonitorFromPoint         = user32.NewProc("MonitorFromPoint")
	procGetMonitorInfoW          = user32.NewProc("GetMonitorInfoW")
	procSetForegroundWindow      = user32.NewProc("SetForegroundWindow")
	procIsIconic                 = user32.NewProc("IsIconic")
	procRedrawWindow             = user32.NewProc("RedrawWindow")
	procGetKeyState              = user32.NewProc("GetKeyState")
	procDrawIconEx               = user32.NewProc("DrawIconEx")
	procDestroyIcon              = user32.NewProc("DestroyIcon")
	procSetWindowLongPtrW        = user32.NewProc("SetWindowLongPtrW")
	procGetWindowLongPtrW        = user32.NewProc("GetWindowLongPtrW")
	procCreateCompatibleDC       = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap   = gdi32.NewProc("CreateCompatibleBitmap")
	procBitBlt                   = gdi32.NewProc("BitBlt")
	procDeleteDC                 = gdi32.NewProc("DeleteDC")
	procGetTextExtentPoint32W    = gdi32.NewProc("GetTextExtentPoint32W")
	procGetTextFaceW             = gdi32.NewProc("GetTextFaceW")
	procPolyline                 = gdi32.NewProc("Polyline")
	procGetStockObject           = gdi32.NewProc("GetStockObject")
	procIsWindowVisible          = user32.NewProc("IsWindowVisible")
	procSHDefExtractIconW        = windows.NewLazySystemDLL("shell32.dll").NewProc("SHDefExtractIconW")
)

// Window messages and styles the toolkit uses.
const (
	wmCreate          = 0x0001
	wmDestroy         = 0x0002
	wmSize            = 0x0005
	wmPaint           = 0x000F
	wmClose           = 0x0010
	wmSettingChange   = 0x001A
	wmGetMinMaxInfo   = 0x0024
	wmMeasureItem     = 0x002C
	wmContextMenu     = 0x007B
	wmNCCreate        = 0x0081
	wmKeyDown         = 0x0100
	wmVKeyToItem      = 0x002E
	wmCtlColorListBox = 0x0134
	wmDpiChanged      = 0x02E0
	wmApp             = 0x8000

	wsOverlappedWindow = 0x00CF0000
	wsClipChildren     = 0x02000000
	wsVScroll          = 0x00200000
	wsHScroll          = 0x00100000
	wsThickFrame       = 0x00040000
	wsExControlParent  = 0x00010000

	esMultiline   = 0x0004
	esAutoVScroll = 0x0040
	esNoHideSel   = 0x0100
	esWantReturn  = 0x1000

	lbsNotify            = 0x0001
	lbsOwnerDrawFixed    = 0x0010
	lbsHasStrings        = 0x0040
	lbsNoIntegralHeight  = 0x0100
	lbsExtendedSel       = 0x0800
	lbsWantKeyboardInput = 0x0400

	lbAddString     = 0x0180
	lbResetContent  = 0x0184
	lbSetSel        = 0x0185
	lbSetCurSel     = 0x0186
	lbGetCurSel     = 0x0188
	lbGetCount      = 0x018B
	lbSetTopIndex   = 0x0197
	lbGetTopIndex   = 0x018E
	lbGetSelCount   = 0x0190
	lbGetSelItems   = 0x0191
	lbSetItemHeight = 0x01A0
	lbItemFromPoint = 0x01A9
	lbnSelChange    = 1

	enSetFocus  = 0x0100
	enKillFocus = 0x0200
	enChange    = 0x0300

	emSetSel        = 0x00B1
	emSetMargins    = 0x00D3
	emSetCueBanner  = 0x1501
	ecLeftMargin    = 1
	ecRightMargin   = 2
	bnClicked       = 0
	swHide          = 0
	swShowNormal    = 1
	swShowNA        = 8
	swRestore       = 9
	swpNoActivate   = 0x0010
	swpNoCopyBits   = 0x0100
	tpmReturnCmd    = 0x0100
	tpmRightButton  = 0x0002
	mfString        = 0x0000
	mfGrayed        = 0x0001
	mfChecked       = 0x0008
	mfSeparator     = 0x0800
	gaRoot          = 2
	idcArrow        = 32512
	srcCopy         = 0x00CC0020
	nullBrush       = 5
	rdwInvalidate   = 0x0001
	rdwErase        = 0x0004
	rdwAllChildren  = 0x0080
	rdwFrame        = 0x0400
	odtListBox      = 2
	vkDelete        = 0x2E
	vkF2            = 0x71
	vkControl       = 0x11
	vkShift         = 0x10
	vkInsert        = 0x2D
	spiNonClientMet = 0x0029
)

// Glyphs of Segoe Fluent Icons, which Segoe MDL2 Assets shares.
const (
	glyphChevronDown  = '\uE70D'
	glyphEdit         = '\uE70F'
	glyphAdd          = '\uE710'
	glyphCheckbox     = '\uE739'
	glyphCheckboxFill = '\uE73B'
	glyphCheckMark    = '\uE73E'
	glyphDelete       = '\uE74D'
	glyphGlobe        = '\uE774'
	glyphCopy         = '\uE8C8'
	glyphCircleRing   = '\uEA3A'
	glyphCircleFill   = '\uEA3B'
	glyphRadioOff     = '\uECCA'
	glyphRefresh      = '\uE72C'
	glyphView         = '\uE890'
	glyphHide         = '\uED1A'
)

type kind int

const (
	kindButton kind = iota
	kindCheck
	kindRadio
	kindTab
	kindIcon // a glyph without a frame
	kindEdit
	kindList
	kindLabel // text the window paints
)

// Label colors.
const (
	labelText = iota
	labelSubtle
	labelError
	labelCaution
	labelSuccess
)

// Fonts.
const (
	fontNormal = iota
	fontSemibold
	fontTitle
	fontMono
	fontCount
)

// control is one element of a form.
type control struct {
	id   uint16
	kind kind
	hwnd uintptr
	text string
	// glyph shows before the text of a button.
	glyph rune
	// primary fills a button with the accent color; on is the state of a
	// checkbox, radio button or tab, and the selection of a segment.
	primary, on bool
	// menu adds a chevron to a button that opens a menu.
	menu bool
	// font and color style a label; wrap lets it take several lines.
	font, color int
	wrap        bool
	// r is the control's place, the field around an edit box or list.
	r      rect
	hidden bool
	// placed is where the control's window is.
	placed rect
	// itemHeight is a list's row height in device-independent pixels, and
	// drawItem paints row i.
	itemHeight int
	drawItem   func(dc uintptr, i int, r rect, selected bool)
	// empty is the text a list shows without rows; checks draws the
	// selection of a list as checkboxes, leaving its rows unshaded.
	empty  string
	checks bool
	// warn outlines an edit box whose text has a problem.
	warn bool
	// tip is the control's tooltip; tipped reports that it has one.
	tip    string
	tipped bool
	// rich makes an edit box a rich edit control, whose text can carry
	// colors; doc is its text object model.
	rich bool
	doc  *comObject
}

// colors are a form's palette as COLORREF values.
type colors struct {
	dark                                bool
	bg, field, border, text, subtext    uint32
	disabled, selected, accent, onAccnt uint32
	err, caution, success, sent         uint32
}

func formColors() colors {
	if highContrast() {
		sys := func(i uintptr) uint32 { c, _, _ := procGetSysColor.Call(i); return uint32(c) }
		const colorWindow, colorWindowText, colorHighlight, colorHighlightText, colorBtnFace, colorGrayText = 5, 8, 13, 14, 15, 17
		return colors{bg: sys(colorBtnFace), field: sys(colorWindow), border: sys(colorWindowText), text: sys(colorWindowText),
			subtext: sys(colorWindowText), disabled: sys(colorGrayText), selected: sys(colorHighlight),
			accent: sys(colorHighlight), onAccnt: sys(colorHighlightText), err: sys(colorWindowText),
			caution: sys(colorWindowText), success: sys(colorWindowText), sent: sys(colorWindowText)}
	}
	if darkMode() {
		return colors{dark: true, bg: rgb(0x20, 0x20, 0x20), field: rgb(0x2b, 0x2b, 0x2b), border: rgb(0x3d, 0x3d, 0x3d),
			text: rgb(0xff, 0xff, 0xff), subtext: rgb(0xab, 0xab, 0xab), disabled: rgb(0x6e, 0x6e, 0x6e),
			selected: rgb(0x3a, 0x3a, 0x3a), accent: accent(1, rgb(0x4c, 0xc2, 0xff)), onAccnt: rgb(0, 0, 0),
			err: rgb(0xff, 0x99, 0xa4), caution: rgb(0xfc, 0xe1, 0x00), success: rgb(0x6c, 0xcb, 0x5f), sent: rgb(0xd5, 0xa6, 0xff)}
	}
	return colors{bg: rgb(0xf3, 0xf3, 0xf3), field: rgb(0xff, 0xff, 0xff), border: rgb(0xe0, 0xe0, 0xe0),
		text: rgb(0x1a, 0x1a, 0x1a), subtext: rgb(0x5d, 0x5d, 0x5d), disabled: rgb(0xa0, 0xa0, 0xa0),
		selected: rgb(0xe8, 0xe8, 0xe8), accent: accent(4, rgb(0x00, 0x5f, 0xb8)), onAccnt: rgb(0xff, 0xff, 0xff),
		err: rgb(0xc4, 0x2b, 0x1c), caution: rgb(0x9d, 0x5d, 0x00), success: rgb(0x0f, 0x7b, 0x0f), sent: rgb(0x87, 0x64, 0xb8)}
}

// palette is the dialog palette of the form's colors, for its buttons.
func (c colors) palette() palette {
	return palette{dark: c.dark, content: c.bg, footer: c.bg, text: c.text, subtext: c.disabled, edit: c.field}
}

// form is a top-level window built from controls.
type form struct {
	hwnd     uintptr
	dpi      int32
	col      colors
	brushes  map[uint32]uintptr
	fonts    [fontCount]uintptr
	iconFace string
	icons    map[int32]uintptr // icon fonts by pixel size

	controls []*control
	byID     map[uint16]*control
	byHwnd   map[uintptr]*control
	nextID   uint16

	// minW and minH are the smallest client size in device-independent pixels.
	minW, minH int32
	// layout places the controls once ready reports that they exist.
	ready   bool
	layout  func(w, h int32)
	paint   func(dc uintptr)
	command func(c *control, code uint16)
	// enter and escape handle the Enter and Esc keys, and save Ctrl+S.
	enter, escape, save func()
	// key handles a key pressed in a list; true consumes it.
	key       func(c *control, vk uint16) bool
	menuAt    func(c *control, x, y int32)
	close     func()
	destroyed func()
	// message handles messages the toolkit leaves alone.
	message func(msg, wparam, lparam uintptr) (uintptr, bool)
	// restyle runs after the colors or the DPI change.
	restyle func()
	// tips is the tooltip control.
	tips uintptr
}

var (
	formsMu     sync.Mutex
	forms       = make(map[uintptr]*form)
	creating    *form
	formProc    = windows.NewCallback(formProcFunc)
	formClass   = windows.StringToUTF16Ptr("splitwireForm")
	classOnce   sync.Once
	appInstance windows.Handle
)

func registerFormClass() {
	classOnce.Do(func() {
		windows.GetModuleHandleEx(0, nil, &appInstance)
		cursor, _, _ := procLoadCursorW.Call(0, idcArrow)
		const imageIcon, lrDefaultSize, lrShared = 1, 0x40, 0x8000
		icon, _, _ := procLoadImageW.Call(uintptr(appInstance), uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("APP"))), imageIcon, 0, 0, lrDefaultSize|lrShared)
		wc := struct {
			size, style                uint32
			proc                       uintptr
			clsExtra, wndExtra         int32
			instance, icon, cursor, bg uintptr
			menuName, className        *uint16
			iconSm                     uintptr
		}{proc: formProc, instance: uintptr(appInstance), icon: icon, cursor: cursor, className: formClass, iconSm: icon}
		wc.size = uint32(unsafe.Sizeof(wc))
		procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	})
}

// newForm creates a hidden top-level window with the client size in
// device-independent pixels, centered on the monitor under the cursor.
func newForm(f *form, title string, owner uintptr, style uint32, w, h int32) {
	registerFormClass()
	f.byID = make(map[uint16]*control)
	f.byHwnd = make(map[uintptr]*control)
	f.brushes = make(map[uint32]uintptr)
	f.icons = make(map[int32]uintptr)
	f.col = formColors()
	f.nextID = 1000

	var pt struct{ x, y int32 }
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	const monitorDefaultToNearest = 2
	mon, _, _ := procMonitorFromPoint.Call(uintptr(*(*uint64)(unsafe.Pointer(&pt))), monitorDefaultToNearest)
	mi := struct {
		size        uint32
		monitor, wa rect
		flags       uint32
	}{}
	mi.size = uint32(unsafe.Sizeof(mi))
	procGetMonitorInfoW.Call(mon, uintptr(unsafe.Pointer(&mi)))

	creating = f
	t, _ := windows.UTF16PtrFromString(title)
	procCreateWindowExW.Call(wsExControlParent, uintptr(unsafe.Pointer(formClass)), uintptr(unsafe.Pointer(t)),
		uintptr(style|wsClipChildren), uintptr(mi.wa.left), uintptr(mi.wa.top), 100, 100, owner, 0, uintptr(appInstance), 0)
	creating = nil
	f.applyTheme()

	r := rect{right: f.px(w), bottom: f.px(h)}
	procAdjustWindowRectExForDpi.Call(uintptr(unsafe.Pointer(&r)), uintptr(style), 0, wsExControlParent, uintptr(f.dpi))
	ww, wh := r.right-r.left, r.bottom-r.top
	x := mi.wa.left + (mi.wa.right-mi.wa.left-ww)/2
	y := mi.wa.top + (mi.wa.bottom-mi.wa.top-wh)/2
	procSetWindowPos.Call(f.hwnd, 0, uintptr(x), uintptr(y), uintptr(ww), uintptr(wh), swpNoZOrder|swpNoActivate)
}

// px scales device-independent pixels to the window's DPI.
func (f *form) px(v int32) int32 { return v * f.dpi / 96 }

func (f *form) brush(c uint32) uintptr {
	if b, ok := f.brushes[c]; ok {
		return b
	}
	b, _, _ := procCreateSolidBrush.Call(uintptr(c))
	f.brushes[c] = b
	return b
}

func (f *form) freeBrushes() {
	for _, b := range f.brushes {
		procDeleteObject.Call(b)
	}
	f.brushes = make(map[uint32]uintptr)
}

// makeFonts creates the fonts for the window's DPI from the system's
// message font.
func (f *form) makeFonts() {
	for i, h := range f.fonts {
		if h != 0 {
			procDeleteObject.Call(h)
			f.fonts[i] = 0
		}
	}
	for _, h := range f.icons {
		procDeleteObject.Call(h)
	}
	f.icons = make(map[int32]uintptr)
	var ncm struct {
		size                                  uint32
		borderWidth, scrollWidth, scrollHeigh int32
		captionWidth, captionHeight           int32
		captionFont                           logFont
		smCaptionWidth, smCaptionHeight       int32
		smCaptionFont                         logFont
		menuWidth, menuHeight                 int32
		menuFont, statusFont, messageFont     logFont
		paddedBorderWidth                     int32
	}
	ncm.size = uint32(unsafe.Sizeof(ncm))
	procSystemParametersInfoDpi.Call(spiNonClientMet, uintptr(ncm.size), uintptr(unsafe.Pointer(&ncm)), 0, uintptr(f.dpi))
	base := ncm.messageFont
	mk := func(lf logFont) uintptr {
		h, _, _ := procCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
		return h
	}
	f.fonts[fontNormal] = mk(base)
	semi := base
	semi.weight = 600
	f.fonts[fontSemibold] = mk(semi)
	title := semi
	title.height = -f.px(20)
	f.fonts[fontTitle] = mk(title)
	mono := logFont{height: -f.px(13), weight: 400}
	f.fonts[fontMono] = mk(withFace(mono, f.firstFace(mono, "Cascadia Mono", "Consolas")))
	f.iconFace = f.firstFace(logFont{height: -16}, "Segoe Fluent Icons", "Segoe MDL2 Assets")
}

func withFace(lf logFont, face string) logFont {
	u, _ := windows.UTF16FromString(face)
	copy(lf.faceName[:31], u)
	return lf
}

// firstFace is the first of the font faces the system has.
func (f *form) firstFace(lf logFont, faces ...string) string {
	dc, _, _ := procGetDC.Call(f.hwnd)
	defer procReleaseDC.Call(f.hwnd, dc)
	for _, face := range faces {
		l := withFace(lf, face)
		h, _, _ := procCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&l)))
		old, _, _ := procSelectObject.Call(dc, h)
		var got [32]uint16
		procGetTextFaceW.Call(dc, 32, uintptr(unsafe.Pointer(&got[0])))
		procSelectObject.Call(dc, old)
		procDeleteObject.Call(h)
		if strings.EqualFold(windows.UTF16ToString(got[:]), face) {
			return face
		}
	}
	return faces[len(faces)-1]
}

// iconFont is the glyph font at size device-independent pixels.
func (f *form) iconFont(size int32) uintptr {
	px := f.px(size)
	if h, ok := f.icons[px]; ok {
		return h
	}
	lf := withFace(logFont{height: -px, weight: 400, quality: 5}, f.iconFace)
	h, _, _ := procCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
	f.icons[px] = h
	return h
}

// add creates a control. Labels have no window of their own.
func (f *form) add(c *control) *control {
	if c.id == 0 {
		c.id = f.nextID
		f.nextID++
	}
	f.controls = append(f.controls, c)
	f.byID[c.id] = c
	if c.kind == kindLabel {
		return c
	}
	var class string
	var style uint32 = wsChild | wsVisible
	switch c.kind {
	case kindEdit:
		class = "EDIT"
		style |= wsTabStop | esAutoHScroll
	case kindList:
		class = "LISTBOX"
		style |= wsTabStop | wsVScroll | lbsNotify | lbsOwnerDrawFixed | lbsHasStrings | lbsNoIntegralHeight | lbsWantKeyboardInput
	default:
		class = "BUTTON"
		style |= wsTabStop | bsOwnerDraw
	}
	return f.create(c, class, style)
}

// addEdit creates an edit box with extra styles.
func (f *form) addEdit(c *control, style uint32) *control {
	c.kind = kindEdit
	if c.id == 0 {
		c.id = f.nextID
		f.nextID++
	}
	f.controls = append(f.controls, c)
	f.byID[c.id] = c
	return f.create(c, "EDIT", wsChild|wsVisible|wsTabStop|style)
}

// addList creates a list with extra styles.
func (f *form) addList(c *control, style uint32) *control {
	c.kind = kindList
	if c.id == 0 {
		c.id = f.nextID
		f.nextID++
	}
	f.controls = append(f.controls, c)
	f.byID[c.id] = c
	return f.create(c, "LISTBOX", wsChild|wsVisible|wsTabStop|wsVScroll|lbsNotify|lbsOwnerDrawFixed|lbsHasStrings|lbsNoIntegralHeight|lbsWantKeyboardInput|style)
}

func (f *form) create(c *control, class string, style uint32) *control {
	cl, _ := windows.UTF16PtrFromString(class)
	t, _ := windows.UTF16PtrFromString(c.text)
	h, _, _ := procCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cl)), uintptr(unsafe.Pointer(t)), uintptr(style),
		0, 0, 0, 0, f.hwnd, uintptr(c.id), uintptr(appInstance), 0)
	c.hwnd = h
	f.byHwnd[h] = c
	font := f.fonts[fontNormal]
	if c.font == fontMono {
		font = f.fonts[fontMono]
	}
	procSendMessageW.Call(h, wmSetFont, font, 0)
	if c.kind == kindEdit {
		m := uintptr(f.px(4))
		procSendMessageW.Call(h, emSetMargins, ecLeftMargin|ecRightMargin, m|m<<16)
	}
	f.themeChild(c)
	return c
}

func (f *form) themeChild(c *control) {
	if c.hwnd == 0 {
		return
	}
	switch c.kind {
	case kindEdit, kindList:
		class := "Explorer"
		if c.kind == kindEdit && !c.wrap {
			class = "CFD"
		}
		if f.col.dark {
			class = "DarkMode_" + class
		}
		if allow := uxthemeOrdinal(ordAllowDarkModeForWindow); allow != 0 {
			syscallN(allow, c.hwnd, boolPtr(f.col.dark))
		}
		name, _ := windows.UTF16PtrFromString(class)
		procSetWindowTheme.Call(c.hwnd, uintptr(unsafe.Pointer(name)), 0)
		procSendMessageW.Call(c.hwnd, wmThemeChanged, 0, 0)
		if c.rich {
			f.themeRich(c)
		}
	}
}

func boolPtr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

// applyTheme follows the system's dark mode in the title bar, the
// scrollbars and the colors.
func (f *form) applyTheme() {
	f.col = formColors()
	f.freeBrushes()
	if allow := uxthemeOrdinal(ordAllowDarkModeForWindow); allow != 0 {
		syscallN(allow, f.hwnd, boolPtr(f.col.dark))
	}
	themeWindow(f.hwnd, f.col.palette())
	for _, c := range f.controls {
		f.themeChild(c)
	}
	f.themeTips()
	if f.restyle != nil {
		f.restyle()
	}
	procRedrawWindow.Call(f.hwnd, 0, 0, rdwInvalidate|rdwErase|rdwAllChildren|rdwFrame)
}

// place moves a control to r, in pixels.
func (f *form) place(c *control, r rect) {
	c.r = r
	f.moveTip(c)
	if c.hwnd == 0 {
		return
	}
	in := r
	switch c.kind {
	case kindEdit:
		pad := f.px(2)
		in = rect{r.left + pad, r.top + pad, r.right - pad, r.bottom - pad}
		if !c.wrap {
			// A single line sits in the middle of its field.
			_, lh := f.measure("Ag", f.fonts[fontNormal])
			h := lh + f.px(2)
			in.top = r.top + (r.bottom-r.top-h)/2
			in.bottom = in.top + h
		}
	case kindList:
		pad := f.px(3)
		in = rect{r.left + pad, r.top + pad, r.right - pad, r.bottom - pad}
	}
	if in == c.placed {
		return
	}
	c.placed = in
	// A moved control repaints: copying its old pixels picks up whatever
	// sibling moved over them first.
	procSetWindowPos.Call(c.hwnd, 0, uintptr(in.left), uintptr(in.top), uintptr(in.right-in.left), uintptr(in.bottom-in.top),
		swpNoZOrder|swpNoActivate|swpNoCopyBits)
}

// show hides or shows a control.
func (f *form) show(c *control, on bool) {
	if c.hidden == !on {
		return
	}
	c.hidden = !on
	f.showWindow(c)
	f.moveTip(c)
	f.invalidate(c)
}

// showWindow shows a control's window unless it is hidden or is a list
// without rows, which shows its empty text.
func (f *form) showWindow(c *control) {
	if c.hwnd == 0 {
		return
	}
	on := !c.hidden
	if c.kind == kindList && c.empty != "" && f.listCount(c) == 0 {
		on = false
	}
	// The style bit is the control's own visibility; IsWindowVisible also
	// reports false while the form itself is hidden.
	style, _, _ := procGetWindowLongPtrW.Call(c.hwnd, ^uintptr(15)) // GWL_STYLE is -16
	if on == (style&wsVisible != 0) {
		return
	}
	cmd := uintptr(swHide)
	if on {
		cmd = swShowNA
	}
	procShowWindow.Call(c.hwnd, cmd)
}

func (f *form) enable(c *control, on bool) {
	if c.hwnd != 0 {
		procEnableWindow.Call(c.hwnd, boolPtr(on))
	}
}

func (f *form) enabled(c *control) bool {
	r, _, _ := procIsWindowEnabled.Call(c.hwnd)
	return r != 0
}

func (f *form) invalidate(c *control) {
	r := c.r
	pad := f.px(2)
	r = rect{r.left - pad, r.top - pad, r.right + pad, r.bottom + pad}
	procInvalidateRect.Call(f.hwnd, uintptr(unsafe.Pointer(&r)), 0)
	if c.hwnd != 0 {
		procInvalidateRect.Call(c.hwnd, 0, 0)
	}
}

// setText changes a control's text, repainting it when it differs.
func (f *form) setText(c *control, s string) {
	if c.text == s && c.kind != kindEdit {
		return
	}
	c.text = s
	if c.hwnd != 0 {
		u, _ := windows.UTF16PtrFromString(s)
		procSetWindowTextW.Call(c.hwnd, uintptr(unsafe.Pointer(u)))
	}
	f.invalidate(c)
}

// setOn changes the state of a checkbox, radio button, tab or segment.
func (f *form) setOn(c *control, on bool) {
	if c.on != on {
		c.on = on
		f.invalidate(c)
	}
}

func windowText(h uintptr) string {
	n, _, _ := procGetWindowTextLengthW.Call(h)
	buf := make([]uint16, n+1)
	procGetWindowTextW.Call(h, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return windows.UTF16ToString(buf)
}

func (f *form) measure(s string, font uintptr) (int32, int32) {
	dc, _, _ := procGetDC.Call(f.hwnd)
	defer procReleaseDC.Call(f.hwnd, dc)
	old, _, _ := procSelectObject.Call(dc, font)
	defer procSelectObject.Call(dc, old)
	if s == "" {
		s = " "
	}
	u, _ := windows.UTF16FromString(s)
	var size struct{ cx, cy int32 }
	procGetTextExtentPoint32W.Call(dc, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&size)))
	return size.cx, size.cy
}

// measureWrapped is the height of text wrapped to width.
func (f *form) measureWrapped(s string, font uintptr, width int32) int32 {
	dc, _, _ := procGetDC.Call(f.hwnd)
	defer procReleaseDC.Call(f.hwnd, dc)
	old, _, _ := procSelectObject.Call(dc, font)
	defer procSelectObject.Call(dc, old)
	u, _ := windows.UTF16FromString(s)
	r := rect{right: width}
	procDrawTextW.Call(dc, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&r)), dtCalcRect|dtWordBreak|dtNoPrefix)
	return r.bottom
}

// buttonWidth fits a button to its text.
func (f *form) buttonWidth(c *control) int32 {
	w, _ := f.measure(c.text, f.fonts[fontNormal])
	w += f.px(24)
	if c.glyph != 0 {
		w += f.px(24)
	}
	if c.menu {
		w += f.px(20)
	}
	if min := f.px(80); w < min {
		w = min
	}
	return w
}

// toggleWidth fits a checkbox or radio button to its label.
func (f *form) toggleWidth(c *control) int32 {
	w, _ := f.measure(c.text, f.fonts[fontNormal])
	return w + f.px(32)
}

const (
	dtRight        = 0x0002
	dtEndEllipsis  = 0x8000
	dtPathEllipsis = 0x4000
)

// drawText draws s in r.
func drawText(dc uintptr, s string, r rect, font uintptr, color uint32, flags uintptr) {
	if s == "" {
		return
	}
	u, _ := windows.UTF16FromString(s)
	old, _, _ := procSelectObject.Call(dc, font)
	procSetTextColor.Call(dc, uintptr(color))
	procSetBkMode.Call(dc, bkTransparent)
	procDrawTextW.Call(dc, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&r)), flags|dtNoPrefix)
	procSelectObject.Call(dc, old)
}

// drawGlyph draws an icon glyph centered in r.
func (f *form) drawGlyph(dc uintptr, g rune, size int32, r rect, color uint32) {
	drawText(dc, string(g), r, f.iconFont(size), color, dtCenter|dtVCenter|dtSingleLine)
}

// fillRound fills a rounded rectangle with an outline.
func fillRound(dc uintptr, r rect, radius int32, fill, border uint32) {
	brush, _, _ := procCreateSolidBrush.Call(uintptr(fill))
	pen, _, _ := procCreatePen.Call(psSolid, 1, uintptr(border))
	ob, _, _ := procSelectObject.Call(dc, brush)
	op, _, _ := procSelectObject.Call(dc, pen)
	procRoundRect.Call(dc, uintptr(r.left), uintptr(r.top), uintptr(r.right), uintptr(r.bottom), uintptr(radius), uintptr(radius))
	procSelectObject.Call(dc, ob)
	procSelectObject.Call(dc, op)
	procDeleteObject.Call(brush)
	procDeleteObject.Call(pen)
}

func (f *form) fill(dc uintptr, r rect, c uint32) {
	procFillRect.Call(dc, uintptr(unsafe.Pointer(&r)), f.brush(c))
}

func (f *form) labelColor(c int) uint32 {
	switch c {
	case labelSubtle:
		return f.col.subtext
	case labelError:
		return f.col.err
	case labelCaution:
		return f.col.caution
	case labelSuccess:
		return f.col.success
	}
	return f.col.text
}

// paintForm paints the background, the labels and the fields around edit
// boxes and lists, double-buffered.
func (f *form) paintForm() {
	var ps struct {
		hdc      uintptr
		erase    int32
		paint    rect
		restore  int32
		incUpd   int32
		reserved [32]byte
	}
	hdc, _, _ := procBeginPaint.Call(f.hwnd, uintptr(unsafe.Pointer(&ps)))
	defer procEndPaint.Call(f.hwnd, uintptr(unsafe.Pointer(&ps)))
	var cr rect
	procGetClientRect.Call(f.hwnd, uintptr(unsafe.Pointer(&cr)))
	if cr.right == 0 || cr.bottom == 0 {
		return
	}
	dc, _, _ := procCreateCompatibleDC.Call(hdc)
	bmp, _, _ := procCreateCompatibleBitmap.Call(hdc, uintptr(cr.right), uintptr(cr.bottom))
	oldBmp, _, _ := procSelectObject.Call(dc, bmp)
	f.fill(dc, cr, f.col.bg)

	focus, _, _ := procGetFocus.Call()
	for _, c := range f.controls {
		if c.hidden {
			continue
		}
		switch c.kind {
		case kindLabel:
			flags := uintptr(dtSingleLine | dtEndEllipsis | dtVCenter)
			if c.wrap {
				flags = dtWordBreak
			}
			drawText(dc, c.text, c.r, f.fonts[c.font], f.labelColor(c.color), flags)
		case kindEdit, kindList:
			f.paintField(dc, c, c.hwnd == focus)
		}
	}
	if f.paint != nil {
		f.paint(dc)
	}
	procBitBlt.Call(hdc, 0, 0, uintptr(cr.right), uintptr(cr.bottom), dc, 0, 0, srcCopy)
	procSelectObject.Call(dc, oldBmp)
	procDeleteObject.Call(bmp)
	procDeleteDC.Call(dc)
}

// paintField draws the box around an edit box or list, with an accent line
// under a focused edit box.
func (f *form) paintField(dc uintptr, c *control, focused bool) {
	border := f.col.border
	if c.warn {
		border = f.col.err
	}
	fillRound(dc, c.r, f.px(8), f.col.field, border)
	if c.kind == kindList && c.empty != "" {
		if n, _, _ := procSendMessageW.Call(c.hwnd, lbGetCount, 0, 0); n == 0 {
			r := c.r
			r.left += f.px(12)
			r.right -= f.px(12)
			r.top += f.px(10)
			drawText(dc, c.empty, r, f.fonts[fontNormal], f.col.subtext, dtWordBreak)
		}
	}
	if c.kind == kindEdit && focused && !c.wrap {
		line := rect{c.r.left + f.px(1), c.r.bottom - f.px(2), c.r.right - f.px(1), c.r.bottom}
		f.fill(dc, line, f.col.accent)
	}
}

// drawControl paints an owner-drawn button, checkbox, radio button or tab.
func (f *form) drawControl(c *control, di *drawItem) {
	dc, r := di.hdc, di.rc
	disabled := di.itemState&odsDisabled != 0
	pressed := di.itemState&odsSelected != 0
	focus := di.itemState&odsFocus != 0 && di.itemState&odsNoFocusRc == 0
	f.fill(dc, r, f.col.bg)
	text := f.col.text
	if disabled {
		text = f.col.disabled
	}
	font := f.fonts[fontNormal]
	switch c.kind {
	case kindButton:
		bc := buttonPalette(f.col.palette(), c.primary || c.on)
		if pressed {
			bc.fill, bc.border = shade(bc.fill, 0.85), shade(bc.border, 0.85)
		}
		if disabled {
			bc.text = f.col.disabled
			if c.primary || c.on {
				bc.fill, bc.border = f.col.selected, f.col.selected
			}
		}
		fillRound(dc, r, f.px(8), bc.fill, bc.border)
		inner := r
		if c.menu {
			arrow := rect{r.right - f.px(28), r.top, r.right - f.px(8), r.bottom}
			f.drawGlyph(dc, glyphChevronDown, 10, arrow, bc.text)
			inner.right = arrow.left
			inner.left += f.px(8)
		}
		if c.glyph != 0 {
			tw, _ := f.measure(c.text, font)
			total := f.px(16) + f.px(8) + tw
			x := inner.left + (inner.right-inner.left-total)/2
			f.drawGlyph(dc, c.glyph, 14, rect{x, r.top, x + f.px(16), r.bottom}, bc.text)
			drawText(dc, c.text, rect{x + f.px(24), r.top, inner.right, r.bottom}, font, bc.text, dtSingleLine|dtVCenter)
		} else {
			drawText(dc, c.text, inner, font, bc.text, dtCenter|dtSingleLine|dtVCenter)
		}
	case kindCheck, kindRadio:
		box := rect{r.left, r.top + (r.bottom-r.top-f.px(20))/2, r.left + f.px(20), 0}
		box.bottom = box.top + f.px(20)
		ring := f.col.subtext
		if disabled {
			ring = f.col.disabled
		}
		fillc := f.col.accent
		if disabled {
			fillc = f.col.disabled
		}
		if c.kind == kindCheck {
			if c.on {
				f.drawGlyph(dc, glyphCheckboxFill, 20, box, fillc)
				f.drawGlyph(dc, glyphCheckMark, 14, box, f.col.onAccnt)
			} else {
				f.drawGlyph(dc, glyphCheckbox, 20, box, ring)
			}
		} else {
			if c.on {
				f.drawGlyph(dc, glyphCircleFill, 20, box, fillc)
				f.drawGlyph(dc, glyphCircleFill, 8, box, f.col.onAccnt)
			} else {
				f.drawGlyph(dc, glyphRadioOff, 20, box, ring)
			}
		}
		drawText(dc, c.text, rect{box.right + f.px(10), r.top, r.right, r.bottom}, font, text, dtSingleLine|dtVCenter|dtEndEllipsis)
	case kindTab:
		color := f.col.subtext
		if c.on {
			font, color = f.fonts[fontSemibold], f.col.text
		}
		if disabled {
			color = f.col.disabled
		}
		drawText(dc, c.text, r, font, color, dtCenter|dtSingleLine|dtVCenter)
		if c.on {
			bar := rect{r.left + (r.right-r.left-f.px(16))/2, r.bottom - f.px(3), 0, r.bottom}
			bar.right = bar.left + f.px(16)
			fillRound(dc, bar, f.px(3), f.col.accent, f.col.accent)
		}
	case kindIcon:
		color := f.col.subtext
		if pressed {
			color = f.col.text
		}
		if disabled {
			color = f.col.disabled
		}
		f.drawGlyph(dc, c.glyph, 14, r, color)
	}
	if focus {
		pen, _, _ := procCreatePen.Call(psSolid, uintptr(f.px(2)), uintptr(f.col.text))
		op, _, _ := procSelectObject.Call(dc, pen)
		nb, _, _ := procGetStockObject.Call(nullBrush)
		ob, _, _ := procSelectObject.Call(dc, nb)
		procRoundRect.Call(dc, uintptr(r.left+1), uintptr(r.top+1), uintptr(r.right-1), uintptr(r.bottom-1), uintptr(f.px(8)), uintptr(f.px(8)))
		procSelectObject.Call(dc, op)
		procSelectObject.Call(dc, ob)
		procDeleteObject.Call(pen)
	}
}

// drawListItem paints a list row through the list's drawItem.
func (f *form) drawListItem(c *control, di *drawItem) {
	if int32(di.itemID) < 0 {
		f.fill(di.hdc, di.rc, f.col.field)
		return
	}
	// The row paints into a buffer, then onto the list in one copy.
	r := di.rc
	w, h := r.right-r.left, r.bottom-r.top
	dc, _, _ := procCreateCompatibleDC.Call(di.hdc)
	bmp, _, _ := procCreateCompatibleBitmap.Call(di.hdc, uintptr(w), uintptr(h))
	old, _, _ := procSelectObject.Call(dc, bmp)
	local := rect{0, 0, w, h}
	f.fill(dc, local, f.col.field)
	selected := di.itemState&odsSelected != 0
	inner := rect{local.left + f.px(2), local.top + f.px(2), local.right - f.px(2), local.bottom - f.px(2)}
	switch {
	case selected && !c.checks:
		fillRound(dc, inner, f.px(8), f.col.selected, f.col.selected)
	case di.itemState&odsFocus != 0 && di.itemState&odsNoFocusRc == 0:
		fillRound(dc, inner, f.px(8), f.col.field, f.col.subtext)
	}
	if c.drawItem != nil {
		c.drawItem(dc, int(di.itemID), local, selected)
	}
	procBitBlt.Call(di.hdc, uintptr(r.left), uintptr(r.top), uintptr(w), uintptr(h), dc, 0, 0, srcCopy)
	procSelectObject.Call(dc, old)
	procDeleteObject.Call(bmp)
	procDeleteDC.Call(dc)
}

// accentPill marks the selected row of a single-selection list.
func (f *form) accentPill(dc uintptr, r rect) {
	h := f.px(16)
	pill := rect{r.left + f.px(2), r.top + (r.bottom-r.top-h)/2, r.left + f.px(5), 0}
	pill.bottom = pill.top + h
	fillRound(dc, pill, f.px(3), f.col.accent, f.col.accent)
}

// ---- lists ----

func (f *form) listSet(c *control, items []string) {
	procSendMessageW.Call(c.hwnd, wmSetRedraw, 0, 0)
	top, _, _ := procSendMessageW.Call(c.hwnd, lbGetTopIndex, 0, 0)
	procSendMessageW.Call(c.hwnd, lbResetContent, 0, 0)
	for _, s := range items {
		u, _ := windows.UTF16PtrFromString(s)
		procSendMessageW.Call(c.hwnd, lbAddString, 0, uintptr(unsafe.Pointer(u)))
	}
	procSendMessageW.Call(c.hwnd, lbSetTopIndex, top, 0)
	procSendMessageW.Call(c.hwnd, wmSetRedraw, 1, 0)
	f.showWindow(c)
	f.invalidate(c)
}

func (f *form) listCount(c *control) int {
	n, _, _ := procSendMessageW.Call(c.hwnd, lbGetCount, 0, 0)
	return int(int32(n))
}

func (f *form) listCurSel(c *control) int {
	i, _, _ := procSendMessageW.Call(c.hwnd, lbGetCurSel, 0, 0)
	return int(int32(i))
}

func (f *form) listSetCurSel(c *control, i int) {
	procSendMessageW.Call(c.hwnd, lbSetCurSel, uintptr(i), 0)
}

// listSelected lists the selected rows of a multiple-selection list.
func (f *form) listSelected(c *control) []int {
	n, _, _ := procSendMessageW.Call(c.hwnd, lbGetSelCount, 0, 0)
	if int32(n) <= 0 {
		return nil
	}
	items := make([]int32, n)
	procSendMessageW.Call(c.hwnd, lbGetSelItems, n, uintptr(unsafe.Pointer(&items[0])))
	out := make([]int, n)
	for i, v := range items {
		out[i] = int(v)
	}
	return out
}

func (f *form) listSetSel(c *control, i int, on bool) {
	procSendMessageW.Call(c.hwnd, lbSetSel, boolPtr(on), uintptr(i))
}

// listItemAt is the row under the screen point, or -1.
func (f *form) listItemAt(c *control, x, y int32) int {
	pt := struct{ x, y int32 }{x, y}
	procScreenToClient.Call(c.hwnd, uintptr(unsafe.Pointer(&pt)))
	r, _, _ := procSendMessageW.Call(c.hwnd, lbItemFromPoint, 0, uintptr(uint32(pt.x)&0xffff|uint32(pt.y)<<16))
	if r>>16 != 0 {
		return -1
	}
	return int(r & 0xffff)
}

const wmSetRedraw = 0x000B

// ---- menus ----

type menuItem struct {
	text            string
	disabled, check bool
	run             func()
}

// popup shows a menu at the screen point and runs the chosen item.
func (f *form) popup(items []menuItem, x, y int32) {
	m, _, _ := procCreatePopupMenu.Call()
	defer procDestroyMenu.Call(m)
	for i, it := range items {
		if it.text == "" {
			procAppendMenuW.Call(m, mfSeparator, 0, 0)
			continue
		}
		flags := uintptr(mfString)
		if it.disabled {
			flags |= mfGrayed
		}
		if it.check {
			flags |= mfChecked
		}
		u, _ := windows.UTF16PtrFromString(it.text)
		procAppendMenuW.Call(m, flags, uintptr(i+1), uintptr(unsafe.Pointer(u)))
	}
	cmd, _, _ := procTrackPopupMenuEx.Call(m, tpmReturnCmd|tpmRightButton, uintptr(x), uintptr(y), f.hwnd, 0)
	if cmd > 0 && int(cmd) <= len(items) && items[cmd-1].run != nil {
		items[cmd-1].run()
	}
}

// popupUnder shows a menu below a button.
func (f *form) popupUnder(c *control, items []menuItem) {
	pt := struct{ x, y int32 }{c.r.left, c.r.bottom + f.px(2)}
	procClientToScreen.Call(f.hwnd, uintptr(unsafe.Pointer(&pt)))
	f.popup(items, pt.x, pt.y)
}

// ---- icons ----

// iconCache holds program icons by path and pixel size.
type iconCache map[string]uintptr

func (ic iconCache) get(path string, size int32) uintptr {
	key := strings.ToLower(path) + "|" + string(rune(size))
	if h, ok := ic[key]; ok {
		return h
	}
	var h uintptr
	p, _ := windows.UTF16PtrFromString(path)
	procSHDefExtractIconW.Call(uintptr(unsafe.Pointer(p)), 0, 0, uintptr(unsafe.Pointer(&h)), 0, uintptr(size))
	if h == 0 {
		// The generic program icon of shell32.
		shell, _ := windows.UTF16PtrFromString(`%SystemRoot%\System32\shell32.dll`)
		procSHDefExtractIconW.Call(uintptr(unsafe.Pointer(shell)), 2, 0, uintptr(unsafe.Pointer(&h)), 0, uintptr(size))
	}
	ic[key] = h
	return h
}

func (ic iconCache) free() {
	for k, h := range ic {
		if h != 0 {
			procDestroyIcon.Call(h)
		}
		delete(ic, k)
	}
}

func drawIcon(dc, icon uintptr, x, y, size int32) {
	const diNormal = 0x3
	procDrawIconEx.Call(dc, uintptr(x), uintptr(y), icon, uintptr(size), uintptr(size), 0, 0, diNormal)
}

// ---- messages ----

// runForms dispatches messages for the thread's forms until quit returns
// true or the thread's last form posts WM_QUIT.
func runForms(quit func() bool) {
	var m struct {
		hwnd           uintptr
		message        uint32
		wparam, lparam uintptr
		time           uint32
		pt             struct{ x, y int32 }
		private        uint32
	}
	for quit == nil || !quit() {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			if int32(r) == 0 && quit != nil {
				// Keep the quit for the outer loop.
				procPostQuitMessage.Call(m.wparam)
			}
			return
		}
		root, _, _ := procGetAncestor.Call(m.hwnd, gaRoot)
		formsMu.Lock()
		f := forms[root]
		formsMu.Unlock()
		if f != nil && m.message == wmKeyDown && f.shortcut(uint16(m.wparam)) {
			continue
		}
		if f != nil {
			if r, _, _ := procIsDialogMessageW.Call(root, uintptr(unsafe.Pointer(&m))); r != 0 {
				continue
			}
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// shortcut runs a form's save on Ctrl+S, and pastes text alone into rich
// edit boxes.
func (f *form) shortcut(vk uint16) bool {
	ctrl, _, _ := procGetKeyState.Call(vkControl)
	shift, _, _ := procGetKeyState.Call(vkShift)
	if vk == 'S' && int16(ctrl) < 0 && f.save != nil {
		f.save()
		return true
	}
	if vk == 'V' && int16(ctrl) < 0 || vk == vkInsert && int16(shift) < 0 {
		focus, _, _ := procGetFocus.Call()
		if c := f.byHwnd[focus]; c != nil && c.rich {
			pastePlain(c.hwnd)
			return true
		}
	}
	return false
}

func formProcFunc(hwnd, msg, wparam, lparam uintptr) uintptr {
	formsMu.Lock()
	f := forms[hwnd]
	if f == nil && creating != nil {
		f = creating
		f.hwnd = hwnd
		forms[hwnd] = f
	}
	formsMu.Unlock()
	if f == nil {
		r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
		return r
	}
	if f.message != nil {
		if r, ok := f.message(msg, wparam, lparam); ok {
			return r
		}
	}
	switch msg {
	case wmNCCreate:
		d, _, _ := procGetDpiForWindow.Call(hwnd)
		f.dpi = int32(d)
		if f.dpi == 0 {
			f.dpi = 96
		}
	case wmCreate:
		f.makeFonts()
		return 0
	case wmEraseBkgnd:
		return 1
	case wmPaint:
		f.paintForm()
		return 0
	case wmSize:
		if f.ready && f.layout != nil {
			w, h := int32(lparam&0xffff), int32(lparam>>16&0xffff)
			if w > 0 && h > 0 {
				f.layout(w, h)
				procInvalidateRect.Call(hwnd, 0, 0)
			}
		}
		return 0
	case wmGetMinMaxInfo:
		if f.minW > 0 && f.dpi > 0 {
			r := rect{right: f.px(f.minW), bottom: f.px(f.minH)}
			style, _, _ := procGetWindowLongPtrW.Call(hwnd, ^uintptr(15)) // GWL_STYLE is -16
			procAdjustWindowRectExForDpi.Call(uintptr(unsafe.Pointer(&r)), style, 0, wsExControlParent, uintptr(f.dpi))
			// lparam carries a MINMAXINFO pointer from the system.
			mmi := *(**[10]int32)(unsafe.Pointer(&lparam))
			mmi[6], mmi[7] = r.right-r.left, r.bottom-r.top
		}
		return 0
	case wmDpiChanged:
		f.dpi = int32(wparam & 0xffff)
		f.makeFonts()
		for _, c := range f.controls {
			if c.hwnd == 0 {
				continue
			}
			font := f.fonts[fontNormal]
			if c.font == fontMono {
				font = f.fonts[fontMono]
			}
			procSendMessageW.Call(c.hwnd, wmSetFont, font, 0)
			if c.kind == kindList {
				procSendMessageW.Call(c.hwnd, lbSetItemHeight, 0, uintptr(f.px(int32(c.itemHeight))))
			}
			if c.kind == kindEdit {
				m := uintptr(f.px(4))
				procSendMessageW.Call(c.hwnd, emSetMargins, ecLeftMargin|ecRightMargin, m|m<<16)
			}
		}
		f.themeTips()
		if f.restyle != nil {
			f.restyle()
		}
		// lparam carries the suggested window rectangle from the system.
		r := *(**rect)(unsafe.Pointer(&lparam))
		procSetWindowPos.Call(hwnd, 0, uintptr(r.left), uintptr(r.top), uintptr(r.right-r.left), uintptr(r.bottom-r.top),
			swpNoZOrder|swpNoActivate)
		return 0
	case wmSettingChange:
		// lparam carries the name of the changed setting, or nothing.
		if lparam != 0 && windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&lparam))) == "ImmersiveColorSet" {
			f.applyTheme()
		}
	case wmThemeChanged:
		f.applyTheme()
	case wmCtlColorEdit, wmCtlColorListBox:
		procSetTextColor.Call(wparam, uintptr(f.col.text))
		procSetBkColor.Call(wparam, uintptr(f.col.field))
		return f.brush(f.col.field)
	case wmCtlColorStatic:
		// Read-only edit boxes.
		procSetTextColor.Call(wparam, uintptr(f.col.text))
		procSetBkColor.Call(wparam, uintptr(f.col.field))
		return f.brush(f.col.field)
	case wmMeasureItem:
		// lparam carries a MEASUREITEMSTRUCT pointer from the system.
		mi := *(**[6]uint32)(unsafe.Pointer(&lparam))
		if c := f.byID[uint16(mi[1])]; c != nil {
			mi[4] = uint32(f.px(int32(c.itemHeight)))
		}
		return 1
	case wmDrawItem:
		// lparam carries a DRAWITEMSTRUCT pointer from the system.
		di := *(**drawItem)(unsafe.Pointer(&lparam))
		if c := f.byHwnd[di.hwndItem]; c != nil {
			if di.ctlType == odtListBox {
				f.drawListItem(c, di)
			} else {
				f.drawControl(c, di)
			}
		}
		return 1
	case wmVKeyToItem:
		if c := f.byHwnd[lparam]; c != nil && f.key != nil && f.key(c, uint16(wparam&0xffff)) {
			return ^uintptr(1) // -2: handled
		}
		return ^uintptr(0)
	case wmContextMenu:
		if c := f.byHwnd[wparam]; c != nil && f.menuAt != nil {
			x, y := int32(int16(lparam&0xffff)), int32(int16(lparam>>16&0xffff))
			if lparam == ^uintptr(0) {
				pt := struct{ x, y int32 }{c.r.left + f.px(16), c.r.top + f.px(16)}
				procClientToScreen.Call(hwnd, uintptr(unsafe.Pointer(&pt)))
				x, y = pt.x, pt.y
			}
			f.menuAt(c, x, y)
			return 0
		}
	case wmCommand:
		id, code := uint16(wparam&0xffff), uint16(wparam>>16&0xffff)
		if lparam == 0 || id == idOK || id == idCancel {
			switch id {
			case idOK:
				if f.enter != nil {
					f.enter()
				}
			case idCancel:
				if f.escape != nil {
					f.escape()
				}
			}
			return 0
		}
		c := f.byHwnd[lparam]
		if c == nil {
			return 0
		}
		if c.kind == kindEdit && (code == enSetFocus || code == enKillFocus) {
			f.invalidate(c)
		}
		if f.command != nil {
			f.command(c, code)
		}
		return 0
	case wmClose:
		if f.close != nil {
			f.close()
			return 0
		}
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		formsMu.Lock()
		delete(forms, hwnd)
		formsMu.Unlock()
		f.freeBrushes()
		for _, h := range f.fonts {
			procDeleteObject.Call(h)
		}
		for _, h := range f.icons {
			procDeleteObject.Call(h)
		}
		if f.destroyed != nil {
			f.destroyed()
		}
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

// onUIThread runs fn on a new thread for windows, which ends when fn
// returns.
func onUIThread(fn func()) {
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		fn()
	}()
}

func postMessage(hwnd, msg uintptr) {
	procPostMessageW.Call(hwnd, msg, 0, 0)
}

func messageBox(owner uintptr, text string, flags uint32) int32 {
	t, _ := windows.UTF16PtrFromString(text)
	caption, _ := windows.UTF16PtrFromString("SplitWire")
	r, _ := windows.MessageBox(windows.HWND(owner), t, caption, flags)
	return r
}

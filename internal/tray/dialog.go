package tray

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                      = windows.NewLazySystemDLL("user32.dll")
	kernel32                    = windows.NewLazySystemDLL("kernel32.dll")
	gdi32                       = windows.NewLazySystemDLL("gdi32.dll")
	procDialogBoxIndirectParamW = user32.NewProc("DialogBoxIndirectParamW")
	procEndDialog               = user32.NewProc("EndDialog")
	procSetDlgItemTextW         = user32.NewProc("SetDlgItemTextW")
	procGetDlgItemTextW         = user32.NewProc("GetDlgItemTextW")
	procSendDlgItemMessageW     = user32.NewProc("SendDlgItemMessageW")
	procCheckDlgButton          = user32.NewProc("CheckDlgButton")
	procIsDlgButtonChecked      = user32.NewProc("IsDlgButtonChecked")
	procGetDlgItem              = user32.NewProc("GetDlgItem")
	procGetDlgCtrlID            = user32.NewProc("GetDlgCtrlID")
	procEnableWindow            = user32.NewProc("EnableWindow")
	procGetSysColor             = user32.NewProc("GetSysColor")
	procSetTextColor            = gdi32.NewProc("SetTextColor")
	procSetBkMode               = gdi32.NewProc("SetBkMode")
	procOpenClipboard           = user32.NewProc("OpenClipboard")
	procEmptyClipboard          = user32.NewProc("EmptyClipboard")
	procSetClipboardData        = user32.NewProc("SetClipboardData")
	procCloseClipboard          = user32.NewProc("CloseClipboard")
	procGlobalAlloc             = kernel32.NewProc("GlobalAlloc")
	procGlobalLock              = kernel32.NewProc("GlobalLock")
	procGlobalUnlock            = kernel32.NewProc("GlobalUnlock")
	procGlobalFree              = kernel32.NewProc("GlobalFree")
	procRtlMoveMemory           = kernel32.NewProc("RtlMoveMemory")
	procMapDialogRect           = user32.NewProc("MapDialogRect")
	procGetWindowRect           = user32.NewProc("GetWindowRect")
	procGetClientRect           = user32.NewProc("GetClientRect")
	procMapWindowPoints         = user32.NewProc("MapWindowPoints")
	procSetWindowPos            = user32.NewProc("SetWindowPos")
	procSendMessageW            = user32.NewProc("SendMessageW")
	procGetDC                   = user32.NewProc("GetDC")
	procReleaseDC               = user32.NewProc("ReleaseDC")
	procDrawTextW               = user32.NewProc("DrawTextW")
	procSelectObject            = gdi32.NewProc("SelectObject")
	procIsWindowEnabled         = user32.NewProc("IsWindowEnabled")
)

// Window messages, styles and system values the dialogs use.
const (
	wmInitDialog     = 0x0110
	wmCommand        = 0x0111
	wmCtlColorStatic = 0x0138
	wmCtlColorDlg    = 0x0136
	wmCtlColorEdit   = 0x0133
	wmCtlColorBtn    = 0x0135
	wmEraseBkgnd     = 0x0014
	bmClick          = 0x00F5
	ssNotify         = 0x0100
	stnClicked       = 0
	stnDblClk        = 1
	emLimitText      = 0x00C5
	bstChecked       = 1
	bkTransparent    = 1
	dsSetFont        = 0x40
	dsModalFrame     = 0x80
	dsSetForeground  = 0x200
	dsCenter         = 0x800
	wsPopup          = 0x80000000
	wsCaption        = 0x00C00000
	wsSysMenu        = 0x00080000
	wsChild          = 0x40000000
	wsVisible        = 0x10000000
	wsExClientEdge   = 0x00000200
	wsTabStop        = 0x00010000
	esAutoHScroll    = 0x0080
	esNumber         = 0x2000
	bsDefPushButton  = 0x0001
	bsAutoCheckBox   = 0x0003
	classButton      = 0x0080
	classEdit        = 0x0081
	classStatic      = 0x0082
	ssNoPrefix       = 0x0080
	wmGetFont        = 0x0031
	dtCalcRect       = 0x0400
	dtWordBreak      = 0x0010
	dtNoPrefix       = 0x0800
	swpNoSize        = 0x0001
	swpNoMove        = 0x0002
	swpNoZOrder      = 0x0004
)

// Control IDs.
const (
	idOK          = 1
	idCancel      = 2
	idIntro       = 99
	idEdit        = 100
	idFirstCheck  = 200 // checkbox of option i is idFirstCheck+i
	idFirstDetail = 300 // its description is idFirstDetail+i
	idFirstLabel  = 400 // its label is idFirstLabel+i
)

// Layout in dialog units.
const (
	dialogWidth    = 260
	dialogMargin   = 7
	contentWidth   = dialogWidth - 2*dialogMargin
	lineHeight     = 9
	detailLine     = 8
	checkboxHeight = 10
	checkboxBox    = 10 // the checkbox control without its label
	footerPad      = 7  // between the footer's edges and its buttons
	detailIndent   = 12
	buttonWidth    = 50
	buttonHeight   = 14
	// Characters per line for wrapping estimates, on the safe side for
	// Segoe UI 9 at contentWidth.
	charsPerLine       = 56
	detailCharsPerLine = 52
)

// dlgTemplate builds an in-memory DLGTEMPLATE: 16-bit words, with each
// control starting on a 32-bit boundary.
type dlgTemplate struct {
	w     []uint16
	count int
}

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

// countSlot is the index of the control count in the header.
const countSlot = 4

func newTemplate(title string, height int) *dlgTemplate {
	t := &dlgTemplate{}
	t.dword(wsPopup | wsCaption | wsSysMenu | dsModalFrame | dsSetFont | dsCenter | dsSetForeground)
	t.dword(0)
	t.word(0) // control count, kept current by control
	for _, v := range []int{0, 0, dialogWidth, height} {
		t.word(uint16(v))
	}
	t.word(0) // no menu
	t.word(0) // default class
	t.str(title)
	t.word(9)
	t.str("Segoe UI")
	return t
}

func (t *dlgTemplate) control(class, id uint16, style uint32, x, y, cx, cy int, text string) {
	t.controlEx(class, id, style, 0, x, y, cx, cy, text)
}

func (t *dlgTemplate) controlEx(class, id uint16, style, exStyle uint32, x, y, cx, cy int, text string) {
	t.align()
	t.dword(style | wsChild | wsVisible)
	t.dword(exStyle)
	for _, v := range []int{x, y, cx, cy} {
		t.word(uint16(v))
	}
	t.word(id)
	t.word(0xffff)
	t.word(class)
	t.str(text)
	t.word(0) // no creation data
	t.count++
	t.w[countSlot] = uint16(t.count)
}

// buttons adds the OK button, labeled ok, and Cancel at the bottom right,
// drawn by drawButton unless the system draws them.
func (t *dlgTemplate) buttons(y int, ok string) {
	right := dialogWidth - dialogMargin
	okStyle, cancelStyle := uint32(bsDefPushButton), uint32(0)
	if ownerDrawButtons() {
		okStyle, cancelStyle = bsOwnerDraw, bsOwnerDraw
	}
	t.control(classButton, idOK, wsTabStop|okStyle, right-2*buttonWidth-4, y, buttonWidth, buttonHeight, ok)
	t.control(classButton, idCancel, wsTabStop|cancelStyle, right-buttonWidth, y, buttonWidth, buttonHeight, "Cancel")
}

// lines estimates how many lines text wraps to at width characters. The
// template sizes from it are a first guess; layout then fits the dialog to
// the measured text.
func lines(text string, width int) int {
	n := 0
	for _, para := range strings.Split(text, "\n") {
		n++
		col := 0
		for _, w := range strings.Fields(para) {
			if col > 0 && col+1+len(w) > width {
				n++
				col = 0
			}
			if col > 0 {
				col++
			}
			col += len(w)
		}
	}
	return n
}

// dialogSpec drives the open dialog; dialogs run one at a time.
type dialogSpec struct {
	init func(hwnd uintptr)
	// ok reads the dialog when OK is pressed; false keeps it open.
	ok func(hwnd uintptr) bool
	// subtle lists the static controls drawn in the secondary text color.
	subtle map[uintptr]bool
	// labels maps clickable labels to the checkboxes they toggle.
	labels map[uintptr]uintptr

	palette   palette
	brushes   brushes
	footerTop int32
}

var (
	dialogMu   sync.Mutex
	dialogProc = windows.NewCallback(dialogProcFunc)
	openDialog *dialogSpec
)

// runDialog shows the template modally and reports whether OK closed it.
func runDialog(t *dlgTemplate, spec *dialogSpec) bool {
	dialogMu.Lock()
	defer dialogMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	spec.palette = currentPalette()
	spec.brushes = newBrushes(spec.palette)
	defer spec.brushes.free()
	openDialog = spec
	var instance windows.Handle
	windows.GetModuleHandleEx(0, nil, &instance)
	r, _, _ := procDialogBoxIndirectParamW.Call(uintptr(instance), uintptr(unsafe.Pointer(&t.w[0])), 0, dialogProc, 0)
	runtime.KeepAlive(t)
	return r == idOK
}

// themeControls applies the visual style matching the palette to the
// dialog's buttons, checkboxes and edit box.
func themeControls(hwnd uintptr, p palette, ids []uintptr) {
	themeWindow(hwnd, p)
	for _, id := range ids {
		ctrl, _, _ := procGetDlgItem.Call(hwnd, id)
		if ctrl == 0 {
			continue
		}
		if id == idEdit {
			themeControl(ctrl, p, "CFD")
		} else {
			themeControl(ctrl, p, "Explorer")
		}
	}
}

func dialogProcFunc(hwnd, msg, wparam, lparam uintptr) uintptr {
	d := openDialog
	switch msg {
	case wmInitDialog:
		if d.init != nil {
			d.init(hwnd)
		}
		return 1
	case wmEraseBkgnd:
		var r rect
		procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
		content, footer := r, r
		content.bottom, footer.top = d.footerTop, d.footerTop
		procFillRect.Call(wparam, uintptr(unsafe.Pointer(&content)), d.brushes.content)
		procFillRect.Call(wparam, uintptr(unsafe.Pointer(&footer)), d.brushes.footer)
		return 1
	case wmCtlColorDlg:
		return d.brushes.content
	case wmCtlColorStatic:
		color := d.palette.text
		if d.subtle[lparam] {
			color = d.palette.subtext
		}
		procSetTextColor.Call(wparam, uintptr(color))
		procSetBkColor.Call(wparam, uintptr(d.palette.content))
		procSetBkMode.Call(wparam, bkTransparent)
		return d.brushes.content
	case wmCtlColorEdit:
		procSetTextColor.Call(wparam, uintptr(d.palette.text))
		procSetBkColor.Call(wparam, uintptr(d.palette.edit))
		return d.brushes.edit
	case wmCtlColorBtn:
		return d.brushes.footer
	case wmDrawItem:
		const odtButton = 4
		// lparam carries a DRAWITEMSTRUCT pointer from the system.
		di := *(**drawItem)(unsafe.Pointer(&lparam))
		if di.ctlType == odtButton {
			drawButton(hwnd, d, di)
			return 1
		}
	case wmCommand:
		id, code := wparam&0xffff, wparam>>16&0xffff
		ctrl, _, _ := procGetDlgItem.Call(hwnd, id)
		if box, ok := d.labels[ctrl]; ok && (code == stnClicked || code == stnDblClk) {
			if enabled, _, _ := procIsWindowEnabled.Call(box); enabled != 0 {
				procSendMessageW.Call(box, bmClick, 0, 0)
			}
			return 1
		}
		switch id {
		case idOK:
			if d.ok == nil || d.ok(hwnd) {
				procEndDialog.Call(hwnd, idOK)
			}
			return 1
		case idCancel:
			procEndDialog.Call(hwnd, idCancel)
			return 1
		}
	}
	return 0
}

type rect struct{ left, top, right, bottom int32 }

// dluY converts vertical dialog units to pixels for the dialog.
func dluY(hwnd uintptr, n int) int32 {
	r := rect{bottom: int32(n)}
	procMapDialogRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	return r.bottom
}

// childRect is a control's rectangle in the dialog's client coordinates.
func childRect(hwnd, ctrl uintptr) rect {
	var r rect
	procGetWindowRect.Call(ctrl, uintptr(unsafe.Pointer(&r)))
	procMapWindowPoints.Call(0, hwnd, uintptr(unsafe.Pointer(&r)), 2)
	return r
}

// textHeight measures text wrapped to the width of the static control.
func textHeight(ctrl uintptr, text string, width int32) int32 {
	font, _, _ := procSendMessageW.Call(ctrl, wmGetFont, 0, 0)
	dc, _, _ := procGetDC.Call(ctrl)
	defer procReleaseDC.Call(ctrl, dc)
	old, _, _ := procSelectObject.Call(dc, font)
	defer procSelectObject.Call(dc, old)
	u, _ := windows.UTF16FromString(text)
	r := rect{right: width}
	procDrawTextW.Call(dc, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)-1), uintptr(unsafe.Pointer(&r)),
		dtCalcRect|dtWordBreak|dtNoPrefix)
	return r.bottom
}

// row is a control placed gap dialog units below the previous row, or
// beside it, vertically centered, with sameRow. A row with text is a
// static control sized to fit it.
type row struct {
	id      uint16
	gap     int
	text    string
	sameRow bool
}

// layout stacks the rows from the top margin, puts the OK and Cancel
// buttons in a footer below them, and resizes the dialog to fit, keeping
// it centered.
func layout(hwnd uintptr, d *dialogSpec, rows []row, buttonGap int) {
	y := dluY(hwnd, dialogMargin)
	var rowTop, rowBottom int32
	for i, r := range rows {
		ctrl, _, _ := procGetDlgItem.Call(hwnd, uintptr(r.id))
		cr := childRect(hwnd, ctrl)
		h := cr.bottom - cr.top
		if r.text != "" {
			h = textHeight(ctrl, r.text, cr.right-cr.left)
		}
		top := y
		switch {
		case r.sameRow:
			top = rowTop
			if h < rowBottom-rowTop {
				top += (rowBottom - rowTop - h) / 2
			}
		case i > 0:
			top += dluY(hwnd, r.gap)
			rowTop = top
		default:
			rowTop = top
		}
		procSetWindowPos.Call(ctrl, 0, uintptr(cr.left), uintptr(top), uintptr(cr.right-cr.left), uintptr(h), swpNoZOrder)
		if !r.sameRow {
			rowBottom = top + h
		} else if top+h > rowBottom {
			rowBottom = top + h
		}
		y = rowBottom
	}
	d.footerTop = y + dluY(hwnd, buttonGap)
	buttonY := d.footerTop + dluY(hwnd, footerPad)
	var buttonH int32
	for _, id := range []uintptr{idOK, idCancel} {
		ctrl, _, _ := procGetDlgItem.Call(hwnd, id)
		cr := childRect(hwnd, ctrl)
		buttonH = cr.bottom - cr.top
		procSetWindowPos.Call(ctrl, 0, uintptr(cr.left), uintptr(buttonY), 0, 0, swpNoSize|swpNoZOrder)
	}
	clientH := buttonY + buttonH + dluY(hwnd, footerPad)

	var win, client rect
	procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&win)))
	procGetClientRect.Call(hwnd, uintptr(unsafe.Pointer(&client)))
	frame := (win.bottom - win.top) - client.bottom
	newH := clientH + frame
	top := win.top - (newH-(win.bottom-win.top))/2
	procSetWindowPos.Call(hwnd, 0, uintptr(win.left), uintptr(top), uintptr(win.right-win.left), uintptr(newH), swpNoZOrder)
}

func warnBox(hwnd uintptr, text string) {
	t, _ := windows.UTF16PtrFromString(text)
	caption, _ := windows.UTF16PtrFromString("splitwire")
	windows.MessageBox(windows.HWND(hwnd), t, caption, windows.MB_OK|windows.MB_ICONWARNING)
}

// askPort shows a dialog for a port number. validate rejects an entry
// with an error, which the dialog shows while it stays open. It reports
// false when canceled.
func askPort(title, prompt string, current uint16, validate func(uint16) error) (uint16, bool) {
	promptHeight := lines(prompt, charsPerLine) * lineHeight
	editY := dialogMargin + promptHeight + 4
	buttonY := editY + 20
	t := newTemplate(title, buttonY+buttonHeight+dialogMargin)
	t.control(classStatic, idIntro, ssNoPrefix, dialogMargin, dialogMargin, contentWidth, promptHeight, prompt)
	t.controlEx(classEdit, idEdit, wsTabStop|esNumber|esAutoHScroll, wsExClientEdge, dialogMargin, editY, 60, 14, "")
	t.buttons(buttonY, "OK")

	initial := ""
	if current != 0 {
		initial = strconv.Itoa(int(current))
	}
	var result uint16
	spec := &dialogSpec{}
	spec.init = func(hwnd uintptr) {
		themeControls(hwnd, spec.palette, []uintptr{idEdit, idOK, idCancel})
		text, _ := windows.UTF16PtrFromString(initial)
		procSetDlgItemTextW.Call(hwnd, idEdit, uintptr(unsafe.Pointer(text)))
		procSendDlgItemMessageW.Call(hwnd, idEdit, emLimitText, 5, 0)
		layout(hwnd, spec, []row{{id: idIntro, text: prompt}, {id: idEdit, gap: 6}}, 10)
	}
	spec.ok = func(hwnd uintptr) bool {
		var buf [8]uint16
		procGetDlgItemTextW.Call(hwnd, idEdit, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		port, err := strconv.ParseUint(windows.UTF16ToString(buf[:]), 10, 16)
		if err != nil || port == 0 {
			err = fmt.Errorf("enter a port from 1 to 65535")
		} else {
			err = validate(uint16(port))
		}
		if err != nil {
			warnBox(hwnd, err.Error())
			return false
		}
		result = uint16(port)
		return true
	}
	ok := runDialog(t, spec)
	return result, ok
}

// option is a checkbox with a description under it.
type option struct {
	label, detail string
	checked       bool
	// disabled shows the option without letting it change.
	disabled bool
}

// askOptions shows intro, a checkbox for each option, and the OK button
// labeled ok beside Cancel. It reports each option's final state, and
// false when canceled. Each checkbox's label is a separate static control
// that toggles it, so the label follows the dialog's text colors.
func askOptions(title, intro string, opts []option, ok string) ([]bool, bool) {
	introHeight := lines(intro, charsPerLine) * lineHeight
	y := dialogMargin + introHeight + 6
	type placed struct{ y, detailHeight int }
	var at []placed
	for _, o := range opts {
		h := 0
		if o.detail != "" {
			h = lines(o.detail, detailCharsPerLine) * detailLine
		}
		at = append(at, placed{y, h})
		y += checkboxHeight + 1 + h + 6
	}
	buttonY := y + 2
	t := newTemplate(title, buttonY+buttonHeight+dialogMargin)
	t.control(classStatic, idIntro, ssNoPrefix, dialogMargin, dialogMargin, contentWidth, introHeight, intro)
	textX, textW := dialogMargin+detailIndent, contentWidth-detailIndent
	for i, o := range opts {
		t.control(classButton, uint16(idFirstCheck+i), wsTabStop|bsAutoCheckBox, dialogMargin, at[i].y, checkboxBox, checkboxHeight, "")
		t.control(classStatic, uint16(idFirstLabel+i), ssNoPrefix|ssNotify, textX, at[i].y, textW, checkboxHeight, o.label)
		if o.detail != "" {
			t.control(classStatic, uint16(idFirstDetail+i), ssNoPrefix, textX, at[i].y+checkboxHeight+1, textW, at[i].detailHeight, o.detail)
		}
	}
	t.buttons(buttonY, ok)

	states := make([]bool, len(opts))
	spec := &dialogSpec{subtle: make(map[uintptr]bool), labels: make(map[uintptr]uintptr)}
	spec.init = func(hwnd uintptr) {
		item := func(id int) uintptr { h, _, _ := procGetDlgItem.Call(hwnd, uintptr(id)); return h }
		ids := []uintptr{idOK, idCancel}
		rows := []row{{id: idIntro, text: intro}}
		for i, o := range opts {
			box, label := item(idFirstCheck+i), item(idFirstLabel+i)
			ids = append(ids, uintptr(idFirstCheck+i))
			spec.labels[label] = box
			if o.checked {
				procCheckDlgButton.Call(hwnd, uintptr(idFirstCheck+i), bstChecked)
			}
			if o.disabled {
				procEnableWindow.Call(box, 0)
				spec.subtle[label] = true
			}
			rows = append(rows,
				row{id: uint16(idFirstCheck + i), gap: 8},
				row{id: uint16(idFirstLabel + i), text: o.label, sameRow: true})
			if o.detail != "" {
				spec.subtle[item(idFirstDetail+i)] = true
				rows = append(rows, row{id: uint16(idFirstDetail + i), gap: 1, text: o.detail})
			}
		}
		themeControls(hwnd, spec.palette, ids)
		layout(hwnd, spec, rows, 10)
	}
	spec.ok = func(hwnd uintptr) bool {
		for i := range opts {
			r, _, _ := procIsDlgButtonChecked.Call(hwnd, uintptr(idFirstCheck+i))
			states[i] = r == bstChecked
		}
		return true
	}
	accepted := runDialog(t, spec)
	return states, accepted
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

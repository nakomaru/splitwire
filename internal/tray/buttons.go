package tray

import (
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

var (
	procCreatePen  = gdi32.NewProc("CreatePen")
	procRoundRect  = gdi32.NewProc("RoundRect")
	procDrawFocusR = user32.NewProc("DrawFocusRect")
)

const (
	wmDrawItem   = 0x002B
	bsOwnerDraw  = 0x000B
	odsSelected  = 0x0001
	odsDisabled  = 0x0004
	odsFocus     = 0x0010
	odsNoFocusRc = 0x0200
	psSolid      = 0
	dtCenter     = 0x0001
	dtVCenter    = 0x0004
	dtSingleLine = 0x0020
)

// drawItem is DRAWITEMSTRUCT.
type drawItem struct {
	ctlType, ctlID, itemID, itemAction, itemState uint32
	hwndItem, hdc                                 uintptr
	rc                                            rect
	itemData                                      uintptr
}

// buttonColors are a button's fill, border and text.
type buttonColors struct{ fill, border, text uint32 }

// accent reads a shade of the system accent color from the Explorer
// accent palette: Light3, Light2, Light1, base, Dark1, Dark2, Dark3.
func accent(index int, fallback uint32) uint32 {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Explorer\Accent`, registry.QUERY_VALUE)
	if err != nil {
		return fallback
	}
	defer k.Close()
	b, _, err := k.GetBinaryValue("AccentPalette")
	if err != nil || len(b) < 4*(index+1) {
		return fallback
	}
	return rgb(b[4*index], b[4*index+1], b[4*index+2])
}

// buttonPalette follows Windows 11 buttons: the primary one filled with the
// accent color, the other neutral with a border.
func buttonPalette(p palette, primary bool) buttonColors {
	switch {
	case p.dark && primary:
		c := accent(1, rgb(0x4c, 0xc2, 0xff))
		return buttonColors{c, c, rgb(0, 0, 0)}
	case p.dark:
		return buttonColors{rgb(0x37, 0x37, 0x37), rgb(0x45, 0x45, 0x45), rgb(0xff, 0xff, 0xff)}
	case primary:
		c := accent(4, rgb(0x00, 0x5f, 0xb8))
		return buttonColors{c, c, rgb(0xff, 0xff, 0xff)}
	}
	return buttonColors{rgb(0xfd, 0xfd, 0xfd), rgb(0xd0, 0xd0, 0xd0), rgb(0x1a, 0x1a, 0x1a)}
}

// shade darkens a color by f, for a pressed button.
func shade(c uint32, f float64) uint32 {
	ch := func(s uint) uint8 { return uint8(float64(c>>s&0xff) * f) }
	return rgb(ch(0), ch(8), ch(16))
}

// drawButton paints an owner-drawn push button.
func drawButton(hwnd uintptr, d *dialogSpec, di *drawItem) {
	c := buttonPalette(d.palette, di.ctlID == idOK)
	if di.itemState&odsSelected != 0 {
		c.fill, c.border = shade(c.fill, 0.85), shade(c.border, 0.85)
	}
	if di.itemState&odsDisabled != 0 {
		c.text = d.palette.subtext
	}
	// The footer shows through the rounded corners.
	procFillRect.Call(di.hdc, uintptr(unsafe.Pointer(&di.rc)), d.brushes.footer)
	brush, _, _ := procCreateSolidBrush.Call(uintptr(c.fill))
	pen, _, _ := procCreatePen.Call(psSolid, 1, uintptr(c.border))
	oldBrush, _, _ := procSelectObject.Call(di.hdc, brush)
	oldPen, _, _ := procSelectObject.Call(di.hdc, pen)
	radius := dluY(hwnd, 2) * 2
	procRoundRect.Call(di.hdc, uintptr(di.rc.left), uintptr(di.rc.top), uintptr(di.rc.right), uintptr(di.rc.bottom),
		uintptr(radius), uintptr(radius))
	procSelectObject.Call(di.hdc, oldBrush)
	procSelectObject.Call(di.hdc, oldPen)
	procDeleteObject.Call(brush)
	procDeleteObject.Call(pen)

	var buf [64]uint16
	n, _, _ := procGetWindowTextW.Call(di.hwndItem, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	font, _, _ := procSendMessageW.Call(di.hwndItem, wmGetFont, 0, 0)
	oldFont, _, _ := procSelectObject.Call(di.hdc, font)
	procSetTextColor.Call(di.hdc, uintptr(c.text))
	procSetBkMode.Call(di.hdc, bkTransparent)
	r := di.rc
	procDrawTextW.Call(di.hdc, uintptr(unsafe.Pointer(&buf[0])), n, uintptr(unsafe.Pointer(&r)), dtCenter|dtVCenter|dtSingleLine)
	procSelectObject.Call(di.hdc, oldFont)

	if di.itemState&odsFocus != 0 && di.itemState&odsNoFocusRc == 0 {
		inset := dluY(hwnd, 1) + 1
		f := rect{di.rc.left + inset, di.rc.top + inset, di.rc.right - inset, di.rc.bottom - inset}
		procSetTextColor.Call(di.hdc, uintptr(c.text))
		procDrawFocusR.Call(di.hdc, uintptr(unsafe.Pointer(&f)))
	}
}

var procGetWindowTextW = user32.NewProc("GetWindowTextW")

// ownerDrawButtons reports whether dialogs draw their own push buttons;
// high contrast themes keep the system's.
func ownerDrawButtons() bool { return !highContrast() }

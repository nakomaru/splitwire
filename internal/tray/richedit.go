package tray

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Rich edit controls of Msftedit.dll, for text with colors.

var msftedit = windows.NewLazySystemDLL("Msftedit.dll")

const (
	wmUser            = 0x0400
	wmUndo            = 0x0304
	wmCut             = 0x0300
	wmCopy            = 0x0301
	wmClear           = 0x0303
	emCanUndo         = 0x00C6
	emExGetSel        = wmUser + 52
	emExLimitText     = wmUser + 53
	emExSetSel        = wmUser + 55
	emGetCharFormat   = wmUser + 58
	emGetOleInterface = wmUser + 60
	emPasteSpecial    = wmUser + 64
	emSetBkgndColor   = wmUser + 67
	emSetCharFormat   = wmUser + 68
	emSetEventMask    = wmUser + 69
	emSetTargetDevice = wmUser + 72
	emSetTextMode     = wmUser + 89
	emGetScrollPos    = wmUser + 221
	emSetScrollPos    = wmUser + 222

	enmChange       = 0x00000001
	tmRichText      = 0x2
	tmMultiLevelUnd = 0x8
	cfUnicodeText   = 13

	scfDefault   = 0x0000
	scfSelection = 0x0001
	scfAll       = 0x0004

	cfmBold          = 0x00000001
	cfmItalic        = 0x00000002
	cfmUnderline     = 0x00000004
	cfmUnderlineType = 0x00800000
	cfmBackColor     = 0x04000000
	cfmFace          = 0x20000000
	cfmColor         = 0x40000000
	cfmSize          = 0x80000000
	cfeBold          = 0x00000001
	cfeItalic        = 0x00000002
	cfeUnderline     = 0x00000004
	cfeAutoBackColor = 0x04000000
	cfuUnderlineWave = 8

	tomSuspend = -9999995
	tomResume  = -9999994
)

// charFormat is CHARFORMAT2W.
type charFormat struct {
	size, mask, effects    uint32
	height, offset         int32
	color                  uint32
	charSet, pitch         uint8
	face                   [32]uint16
	weight                 uint16
	spacing                int16
	back                   uint32
	lcid, reserved         uint32
	style                  int16
	kerning                uint16
	underline, animation   uint8
	revAuthor, underlineCl uint8
}

func newCharFormat(mask uint32) charFormat {
	cf := charFormat{mask: mask}
	cf.size = uint32(unsafe.Sizeof(cf))
	return cf
}

// charRange is CHARRANGE.
type charRange struct{ min, max int32 }

// comObject is a COM interface pointer's target.
type comObject struct{ vtbl *[32]uintptr }

func (o *comObject) call(slot int, args ...uintptr) uintptr {
	r, _, _ := syscall.SyscallN(o.vtbl[slot], append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)...)
	return r
}

var iidTextDocument = windows.GUID{Data1: 0x8CC497C0, Data2: 0xA1DF, Data3: 0x11CE, Data4: [8]byte{0x80, 0x98, 0x00, 0xAA, 0x00, 0x47, 0xBE, 0x5D}}

// Slots of the interfaces the rich edit control hands out.
const (
	slotQueryInterface = 0
	slotRelease        = 2
	slotTextDocUndo    = 22 // ITextDocument::Undo
)

// addRich creates a multiline rich edit box that keeps the colors it is
// given and pastes text alone.
func (f *form) addRich(c *control, style uint32) *control {
	msftedit.Load()
	c.kind, c.rich, c.wrap = kindEdit, true, true
	if c.id == 0 {
		c.id = f.nextID
		f.nextID++
	}
	f.controls = append(f.controls, c)
	f.byID[c.id] = c
	f.create(c, "RICHEDIT50W", wsChild|wsVisible|wsTabStop|style)
	h := c.hwnd
	procSendMessageW.Call(h, emSetTextMode, tmRichText|tmMultiLevelUnd, 0)
	procSendMessageW.Call(h, emSetEventMask, 0, enmChange)
	procSendMessageW.Call(h, emExLimitText, 0, 1<<20)
	// Lines run on past the right edge.
	procSendMessageW.Call(h, emSetTargetDevice, 0, 1)
	var ole *comObject
	procSendMessageW.Call(h, emGetOleInterface, 0, uintptr(unsafe.Pointer(&ole)))
	if ole != nil {
		ole.call(slotQueryInterface, uintptr(unsafe.Pointer(&iidTextDocument)), uintptr(unsafe.Pointer(&c.doc)))
		ole.call(slotRelease)
	}
	f.themeRich(c)
	return c
}

// themeRich gives a rich edit box the form's field and text colors.
func (f *form) themeRich(c *control) {
	procSendMessageW.Call(c.hwnd, emSetBkgndColor, 0, uintptr(f.col.field))
	cf := newCharFormat(cfmColor)
	cf.color = f.col.text
	procSendMessageW.Call(c.hwnd, emSetCharFormat, scfDefault, uintptr(unsafe.Pointer(&cf)))
}

// long passes a C long argument.
func long(v int32) uintptr { return uintptr(uint32(v)) }

func pastePlain(h uintptr) {
	procSendMessageW.Call(h, emPasteSpecial, cfUnicodeText, 0)
}

// span is a run of characters in UTF-16 units with a style.
type span struct {
	start, end int
	style      int
}

// richStyle is how a span looks.
type richStyle struct {
	color                   uint32
	bold, italic, squiggled bool
}

// colorize restyles a rich edit box's text: base for all of it, then the
// spans, outside the undo history and with the selection and scroll
// position kept.
func (f *form) colorize(c *control, base richStyle, spans []span, styles map[int]richStyle) {
	h := c.hwnd
	if c.doc != nil {
		c.doc.call(slotTextDocUndo, long(tomSuspend), 0)
		defer c.doc.call(slotTextDocUndo, long(tomResume), 0)
	}
	// Turning redraw back on shows a window, so a hidden one keeps it on.
	style, _, _ := procGetWindowLongPtrW.Call(h, ^uintptr(15)) // GWL_STYLE is -16
	visible := style&wsVisible != 0
	if visible {
		procSendMessageW.Call(h, wmSetRedraw, 0, 0)
	}
	var scroll struct{ x, y int32 }
	procSendMessageW.Call(h, emGetScrollPos, 0, uintptr(unsafe.Pointer(&scroll)))
	var sel charRange
	procSendMessageW.Call(h, emExGetSel, 0, uintptr(unsafe.Pointer(&sel)))

	// The face and size come from the font the box was given, so pasted
	// or dropped text takes them too.
	def := newCharFormat(cfmFace | cfmSize)
	procSendMessageW.Call(h, emGetCharFormat, scfDefault, uintptr(unsafe.Pointer(&def)))
	set := func(flags uintptr, st richStyle, full bool) {
		cf := newCharFormat(cfmColor | cfmBold | cfmItalic | cfmUnderline | cfmUnderlineType)
		if full {
			cf.mask |= cfmFace | cfmSize | cfmBackColor
			cf.face, cf.height, cf.charSet, cf.pitch = def.face, def.height, def.charSet, def.pitch
			cf.effects |= cfeAutoBackColor
		}
		cf.color = st.color
		if st.bold {
			cf.effects |= cfeBold
		}
		if st.italic {
			cf.effects |= cfeItalic
		}
		if st.squiggled {
			cf.effects |= cfeUnderline
			cf.underline = cfuUnderlineWave
		}
		procSendMessageW.Call(h, emSetCharFormat, flags, uintptr(unsafe.Pointer(&cf)))
	}
	set(scfAll, base, true)
	for _, sp := range spans {
		r := charRange{int32(sp.start), int32(sp.end)}
		procSendMessageW.Call(h, emExSetSel, 0, uintptr(unsafe.Pointer(&r)))
		set(scfSelection, styles[sp.style], false)
	}

	procSendMessageW.Call(h, emExSetSel, 0, uintptr(unsafe.Pointer(&sel)))
	procSendMessageW.Call(h, emSetScrollPos, 0, uintptr(unsafe.Pointer(&scroll)))
	if visible {
		procSendMessageW.Call(h, wmSetRedraw, 1, 0)
		procInvalidateRect.Call(h, 0, 0)
	}
}

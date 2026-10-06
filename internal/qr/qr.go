// Package qr reads QR codes from image files, the clipboard and the screen.
package qr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/gif"  // GIF files
	_ "image/jpeg" // JPEG files
	_ "image/png"  // PNG files
	"os"
	"unsafe"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	"golang.org/x/sys/windows"
)

var (
	user32                     = windows.NewLazySystemDLL("user32.dll")
	gdi32                      = windows.NewLazySystemDLL("gdi32.dll")
	kernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard          = user32.NewProc("OpenClipboard")
	procCloseClipboard         = user32.NewProc("CloseClipboard")
	procGetClipboardData       = user32.NewProc("GetClipboardData")
	procGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	procGetDC                  = user32.NewProc("GetDC")
	procReleaseDC              = user32.NewProc("ReleaseDC")
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procBitBlt                 = gdi32.NewProc("BitBlt")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procGlobalLock             = kernel32.NewProc("GlobalLock")
	procGlobalUnlock           = kernel32.NewProc("GlobalUnlock")
	procGlobalSize             = kernel32.NewProc("GlobalSize")
)

const (
	cfDIB          = 8
	smXVirtual     = 76
	smYVirtual     = 77
	smCXVirtual    = 78
	smCYVirtual    = 79
	srcCopy        = 0x00CC0020
	captureBlt     = 0x40000000
	biRGB          = 0
	biBitfields    = 3
	dibRGBColors   = 0
	infoHeaderSize = 40
)

// ErrNone reports an image without a QR code.
var ErrNone = errors.New("no QR code found")

// Decode reads the text of the QR code in img.
func Decode(img image.Image) (string, error) {
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}
	hints := map[gozxing.DecodeHintType]any{gozxing.DecodeHintType_TRY_HARDER: true}
	res, err := qrcode.NewQRCodeReader().Decode(bmp, hints)
	if err != nil {
		return "", ErrNone
	}
	return res.GetText(), nil
}

// File reads a PNG, JPEG, GIF or BMP image.
func File(path string) (image.Image, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > 14 && b[0] == 'B' && b[1] == 'M' {
		return dib(b[14:])
	}
	img, _, err := image.Decode(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s is not a PNG, JPEG, GIF or BMP image", path)
	}
	return img, nil
}

// Clipboard returns the image on the clipboard, such as a screenshot that
// Win+Shift+S took.
func Clipboard() (image.Image, error) {
	if r, _, err := procOpenClipboard.Call(0); r == 0 {
		return nil, err
	}
	defer procCloseClipboard.Call()
	h, _, _ := procGetClipboardData.Call(cfDIB)
	if h == 0 {
		return nil, errors.New("the clipboard holds no image")
	}
	p, _, err := procGlobalLock.Call(h)
	if p == 0 {
		return nil, err
	}
	defer procGlobalUnlock.Call(h)
	n, _, _ := procGlobalSize.Call(h)
	// p points to the clipboard's memory, n bytes long, for as long as it
	// stays locked; dib copies the pixels out.
	return dib(unsafe.Slice(*(**byte)(unsafe.Pointer(&p)), n))
}

// dib decodes a device-independent bitmap of 24 or 32 bits per pixel: a
// BITMAPINFOHEADER or a later header, then the pixels.
func dib(b []byte) (image.Image, error) {
	if len(b) < infoHeaderSize {
		return nil, errors.New("the bitmap is cut short")
	}
	size := int(binary.LittleEndian.Uint32(b))
	width := int(int32(binary.LittleEndian.Uint32(b[4:])))
	height := int(int32(binary.LittleEndian.Uint32(b[8:])))
	bits := int(binary.LittleEndian.Uint16(b[14:]))
	compression := binary.LittleEndian.Uint32(b[16:])
	colors := int(binary.LittleEndian.Uint32(b[32:]))
	if bits != 24 && bits != 32 || compression != biRGB && compression != biBitfields || width <= 0 || height == 0 {
		return nil, fmt.Errorf("the bitmap's format is unsupported: %d bits per pixel, compression %d", bits, compression)
	}
	offset := size + colors*4
	if compression == biBitfields && size == infoHeaderSize {
		offset += 12
	}
	topDown := height < 0
	if topDown {
		height = -height
	}
	stride := (width*bits/8 + 3) &^ 3
	if offset+stride*height > len(b) {
		return nil, errors.New("the bitmap is cut short")
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	px := bits / 8
	for y := range height {
		src := y
		if !topDown {
			src = height - 1 - y
		}
		row := b[offset+src*stride:]
		for x := range width {
			i, o := x*px, img.PixOffset(x, y)
			img.Pix[o], img.Pix[o+1], img.Pix[o+2], img.Pix[o+3] = row[i+2], row[i+1], row[i], 0xff
		}
	}
	return img, nil
}

// Screen captures every monitor as one image.
func Screen() (image.Image, error) {
	metric := func(i uintptr) int32 { v, _, _ := procGetSystemMetrics.Call(i); return int32(v) }
	x, y, w, h := metric(smXVirtual), metric(smYVirtual), metric(smCXVirtual), metric(smCYVirtual)
	if w <= 0 || h <= 0 {
		return nil, errors.New("no screen to capture")
	}
	screen, _, _ := procGetDC.Call(0)
	if screen == 0 {
		return nil, errors.New("could not read the screen")
	}
	defer procReleaseDC.Call(0, screen)
	dc, _, _ := procCreateCompatibleDC.Call(screen)
	defer procDeleteDC.Call(dc)
	bmp, _, _ := procCreateCompatibleBitmap.Call(screen, uintptr(w), uintptr(h))
	defer procDeleteObject.Call(bmp)
	old, _, _ := procSelectObject.Call(dc, bmp)
	r, _, err := procBitBlt.Call(dc, 0, 0, uintptr(w), uintptr(h), screen, uintptr(x), uintptr(y), srcCopy|captureBlt)
	procSelectObject.Call(dc, old)
	if r == 0 {
		return nil, fmt.Errorf("could not read the screen: %w", err)
	}
	// A BITMAPINFOHEADER asking for top-down rows of 32 bits per pixel.
	info := make([]byte, infoHeaderSize)
	binary.LittleEndian.PutUint32(info, infoHeaderSize)
	binary.LittleEndian.PutUint32(info[4:], uint32(w))
	binary.LittleEndian.PutUint32(info[8:], uint32(-h))
	binary.LittleEndian.PutUint16(info[12:], 1)
	binary.LittleEndian.PutUint16(info[14:], 32)
	pixels := make([]byte, int(w)*int(h)*4)
	if r, _, err := procGetDIBits.Call(dc, bmp, 0, uintptr(h), uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&info[0])), dibRGBColors); r == 0 {
		return nil, fmt.Errorf("could not read the screen: %w", err)
	}
	return dib(append(info, pixels...))
}

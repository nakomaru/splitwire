package qr

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

const text = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.8.0.2/32\n\n" +
	"[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 203.0.113.7:51820\n"

func code(t *testing.T) image.Image {
	m, err := qrcode.NewQRCodeWriter().Encode(text, gozxing.BarcodeFormat_QR_CODE, 400, 400, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// bmpFile encodes img as a bottom-up BMP file of bits per pixel.
func bmpFile(img image.Image, bits int) []byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	stride := (w*bits/8 + 3) &^ 3
	var buf bytes.Buffer
	buf.WriteString("BM")
	binary.Write(&buf, binary.LittleEndian, []uint32{uint32(54 + stride*h), 0, 54})
	binary.Write(&buf, binary.LittleEndian, []uint32{40, uint32(w), uint32(h)})
	binary.Write(&buf, binary.LittleEndian, []uint16{1, uint16(bits)})
	binary.Write(&buf, binary.LittleEndian, []uint32{0, uint32(stride * h), 0, 0, 0, 0})
	for y := h - 1; y >= 0; y-- {
		row := make([]byte, stride)
		for x := range w {
			r, g, bl, _ := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			row[x*bits/8], row[x*bits/8+1], row[x*bits/8+2] = byte(bl>>8), byte(g>>8), byte(r>>8)
		}
		buf.Write(row)
	}
	return buf.Bytes()
}

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	var p bytes.Buffer
	if err := png.Encode(&p, code(t)); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"code.png": p.Bytes(), "code24.bmp": bmpFile(code(t), 24), "code32.bmp": bmpFile(code(t), 32)}
	for name, b := range files {
		path := filepath.Join(dir, name)
		os.WriteFile(path, b, 0o600)
		img, err := File(path)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := Decode(img)
		if err != nil || got != text {
			t.Fatalf("%s: %q, %v", name, got, err)
		}
	}
	blank := image.NewRGBA(image.Rect(0, 0, 50, 50))
	if _, err := Decode(blank); err != ErrNone {
		t.Fatalf("blank image: %v", err)
	}
}

func TestScreen(t *testing.T) {
	img, err := Screen()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("screen %v", img.Bounds())
	if _, err := Decode(img); err != nil && err != ErrNone {
		t.Fatal(err)
	}
}

// TestSmallCodeInLargeImage finds a code that fills a corner of a 4K
// screenshot, as a code in a browser window would.
func TestSmallCodeInLargeImage(t *testing.T) {
	m, err := qrcode.NewQRCodeWriter().Encode(text, gozxing.BarcodeFormat_QR_CODE, 200, 200, nil)
	if err != nil {
		t.Fatal(err)
	}
	big := image.NewRGBA(image.Rect(0, 0, 3840, 2160))
	for i := range big.Pix {
		big.Pix[i] = byte(i*7%97) + 80
	}
	for y := range 200 {
		for x := range 200 {
			big.Set(2900+x, 1500+y, m.At(x, y))
		}
	}
	got, err := Decode(big)
	if err != nil || got != text {
		t.Fatalf("%q, %v", got, err)
	}
}

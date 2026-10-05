package tray

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Icon colors by tunnel state.
var (
	colorDown  = color.RGBA{0x8b, 0x94, 0x9e, 0xff}
	colorBusy  = color.RGBA{0xd2, 0x99, 0x22, 0xff}
	colorUp    = color.RGBA{0x2e, 0xa0, 0x43, 0xff}
	colorError = color.RGBA{0xcf, 0x22, 0x2e, 0xff}
)

type point struct{ x, y float64 }

// The glyph is a wire splitting in two, in unit coordinates.
var glyph = [][2]point{
	{{0.50, 0.80}, {0.50, 0.52}},
	{{0.50, 0.52}, {0.28, 0.24}},
	{{0.50, 0.52}, {0.72, 0.24}},
}

func segmentDistance(p, a, b point) float64 {
	dx, dy := b.x-a.x, b.y-a.y
	t := ((p.x-a.x)*dx + (p.y-a.y)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	ex, ey := p.x-(a.x+t*dx), p.y-(a.y+t*dy)
	return math.Hypot(ex, ey)
}

// render draws the icon at size pixels square as straight RGBA rows, top first.
func render(size int, bg color.RGBA) []color.RGBA {
	const samples = 4
	const stroke = 0.075 // half width
	px := make([]color.RGBA, size*size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var discCover, glyphCover float64
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					p := point{
						(float64(x) + (float64(sx)+0.5)/samples) / float64(size),
						(float64(y) + (float64(sy)+0.5)/samples) / float64(size),
					}
					if math.Hypot(p.x-0.5, p.y-0.5) > 0.48 {
						continue
					}
					discCover++
					for _, s := range glyph {
						if segmentDistance(p, s[0], s[1]) <= stroke {
							glyphCover++
							break
						}
					}
				}
			}
			n := float64(samples * samples)
			a := discCover / n
			g := 0.0
			if discCover > 0 {
				g = glyphCover / discCover
			}
			mix := func(c uint8) uint8 { return uint8(float64(c)*(1-g) + 255*g + 0.5) }
			px[y*size+x] = color.RGBA{mix(bg.R), mix(bg.G), mix(bg.B), uint8(a*255 + 0.5)}
		}
	}
	return px
}

// icoBytes encodes the icon in the sizes Windows asks the tray for.
func icoBytes(bg color.RGBA) []byte {
	return encodeIco(bg, []int{16, 20, 24, 32, 40, 48, 64})
}

// AppIcon is the executable's icon: the connected tray icon at the sizes
// Explorer shows, up to 256 pixels.
func AppIcon() []byte {
	return encodeIco(colorUp, []int{16, 20, 24, 32, 40, 48, 64, 96, 128, 256})
}

// encodeIco encodes the icon at each size, as PNG from 48 pixels up. A
// size of 256 is stored as 0, as the format requires.
func encodeIco(bg color.RGBA, sizes []int) []byte {
	var images [][]byte
	for _, s := range sizes {
		px := render(s, bg)
		if s >= 48 {
			images = append(images, pngImage(s, px))
		} else {
			images = append(images, dib(s, px))
		}
	}
	var b bytes.Buffer
	le := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	le(uint16(0))
	le(uint16(1)) // icon
	le(uint16(len(sizes)))
	offset := 6 + 16*len(sizes)
	for i, s := range sizes {
		b.WriteByte(byte(s))
		b.WriteByte(byte(s))
		b.WriteByte(0) // palette
		b.WriteByte(0)
		le(uint16(1))  // planes
		le(uint16(32)) // bits per pixel
		le(uint32(len(images[i])))
		le(uint32(offset))
		offset += len(images[i])
	}
	for _, img := range images {
		b.Write(img)
	}
	return b.Bytes()
}

func pngImage(size int, px []color.RGBA) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for i, c := range px {
		img.Pix[i*4], img.Pix[i*4+1], img.Pix[i*4+2], img.Pix[i*4+3] = c.R, c.G, c.B, c.A
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

// dib is a 32-bit icon bitmap: BITMAPINFOHEADER, bottom-up BGRA rows and
// an all-transparent AND mask, since the alpha channel carries the shape.
func dib(size int, px []color.RGBA) []byte {
	var b bytes.Buffer
	le := func(v any) { binary.Write(&b, binary.LittleEndian, v) }
	le(uint32(40))
	le(int32(size))
	le(int32(size * 2)) // XOR and AND masks
	le(uint16(1))
	le(uint16(32))
	le(uint32(0))
	le(uint32(0))
	le(int32(0))
	le(int32(0))
	le(uint32(0))
	le(uint32(0))
	for y := size - 1; y >= 0; y-- {
		for x := 0; x < size; x++ {
			c := px[y*size+x]
			b.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	maskRow := ((size + 31) / 32) * 4
	b.Write(make([]byte, maskRow*size))
	return b.Bytes()
}

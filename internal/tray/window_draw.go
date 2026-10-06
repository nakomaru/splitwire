package tray

import (
	"unsafe"

	"splitwire/internal/ipc"
	"splitwire/internal/stats"
)

func (w *window) paint(dc uintptr) {
	if !w.graph.empty() {
		w.paintGraph(dc)
	}
}

// stateColors are the dots of tunnels running as the VPN and as proxies.
func (w *window) stateColors() (vpn, proxy uint32) {
	if w.f.col.dark {
		return w.f.col.success, rgb(0x60, 0xcd, 0xff)
	}
	return w.f.col.success, rgb(0x00, 0x5f, 0xb8)
}

// tunnelLine is a tunnel's row in the list: its dot color, whether the dot
// is filled, and its second line with that line's color.
func (w *window) tunnelLine(name string) (uint32, bool, string, uint32) {
	col := w.f.col
	vpn, proxy := w.stateColors()
	file := w.snap.files[name]
	var t *ipc.Tunnel
	if w.snap.link == linkConnected {
		t = w.snap.status.Find(name)
	}
	switch {
	case t != nil && t.State == ipc.StateError:
		return col.err, true, "Failed", col.err
	case t != nil && (t.State == ipc.StateStarting || t.State == ipc.StateStopping):
		return col.caution, true, short(t), col.subtext
	case t != nil && ipc.Adapter(t.As):
		return vpn, true, short(t), col.subtext
	case t != nil:
		return proxy, true, short(t), col.subtext
	case file.error != "":
		return col.err, false, "Has a problem", col.err
	case file.cfg != nil:
		return col.subtext, false, "Off \u00B7 " + offDetail(file.cfg), col.subtext
	}
	return col.subtext, false, "Off", col.subtext
}

func (w *window) drawTunnel(dc uintptr, i int, r rect, selected bool) {
	if i >= len(w.snap.names) {
		return
	}
	f := w.f
	name := w.snap.names[i]
	if selected {
		f.accentPill(dc, r)
	}
	dot, filled, line, lineColor := w.tunnelLine(name)
	g := rune(glyphCircleRing)
	if filled {
		g = glyphCircleFill
	}
	f.drawGlyph(dc, g, 10, rect{r.left + f.px(12), r.top, r.left + f.px(28), r.bottom}, dot)
	x := r.left + f.px(36)
	drawText(dc, name, rect{x, r.top + f.px(7), r.right - f.px(8), r.top + f.px(27)}, f.fonts[fontNormal], f.col.text, dtSingleLine|dtVCenter|dtEndEllipsis)
	drawText(dc, line, rect{x, r.top + f.px(26), r.right - f.px(8), r.bottom - f.px(6)}, f.fonts[fontNormal], lineColor, dtSingleLine|dtVCenter|dtEndEllipsis)
}

func (w *window) drawApp(dc uintptr, i int, r rect, selected bool) {
	if i >= len(w.entries) {
		return
	}
	f := w.f
	e := w.entries[i]
	size := f.px(24)
	drawIcon(dc, w.icons.get(e.icon, size), r.left+f.px(12), r.top+(r.bottom-r.top-size)/2, size)
	x := r.left + f.px(48)
	noteW := int32(0)
	if e.note != "" {
		noteW, _ = f.measure(e.note, f.fonts[fontNormal])
		color := f.col.subtext
		if e.warn {
			color = f.col.caution
		}
		drawText(dc, e.note, rect{r.right - f.px(12) - noteW, r.top, r.right - f.px(12), r.bottom}, f.fonts[fontNormal], color, dtSingleLine|dtVCenter)
		noteW += f.px(16)
	}
	right := r.right - f.px(12) - noteW
	drawText(dc, e.name, rect{x, r.top + f.px(5), right, r.top + f.px(24)}, f.fonts[fontNormal], f.col.text, dtSingleLine|dtVCenter|dtEndEllipsis)
	drawText(dc, e.raw, rect{x, r.top + f.px(23), right, r.bottom - f.px(4)}, f.fonts[fontNormal], f.col.subtext, dtSingleLine|dtVCenter|dtPathEllipsis)
}

// paintGraph draws the selected tunnel's received and sent rates over the
// last minutes.
func (w *window) paintGraph(dc uintptr) {
	f := w.f
	r := w.graph
	fillRound(dc, r, f.px(8), f.col.field, f.col.border)
	tr := w.snap.traffic[w.sel]
	rates := tr.rates()
	_, recvColor := w.stateColors()
	sentColor := f.col.sent
	pad := f.px(14)
	head := rect{r.left + pad, r.top + f.px(8), r.right - pad, r.top + f.px(30)}
	var cur rate
	if len(rates) > 0 {
		cur = rates[len(rates)-1]
	}
	font, bold := f.fonts[fontNormal], f.fonts[fontSemibold]
	down := "\u2193 " + stats.Bytes(uint64(cur.rx)) + "/s"
	up := "\u2191 " + stats.Bytes(uint64(cur.tx)) + "/s"
	drawText(dc, down, head, bold, recvColor, dtSingleLine|dtVCenter)
	dw, _ := f.measure(down, bold)
	drawText(dc, up, rect{head.left + dw + f.px(16), head.top, head.right, head.bottom}, bold, sentColor, dtSingleLine|dtVCenter)
	if n := len(tr.samples); n > 0 {
		last := tr.samples[n-1]
		total := stats.Bytes(last.rx) + " received, " + stats.Bytes(last.tx) + " sent"
		drawText(dc, total, head, font, f.col.subtext, dtSingleLine|dtVCenter|dtRight)
	}

	peak := 1024.0
	for _, p := range rates {
		if p.rx > peak {
			peak = p.rx
		}
		if p.tx > peak {
			peak = p.tx
		}
	}
	// The scale sits in a gutter right of the plot, at its top line.
	scale := stats.Bytes(uint64(peak)) + "/s"
	sw, sh := f.measure(scale, font)
	plot := rect{r.left + pad, head.bottom + f.px(10), r.right - pad - sw - f.px(12), r.bottom - f.px(12)}
	f.fill(dc, rect{plot.left, plot.bottom, plot.right, plot.bottom + 1}, f.col.border)
	if len(rates) == 0 {
		return
	}
	f.fill(dc, rect{plot.left, plot.top, plot.right, plot.top + 1}, f.col.selected)
	drawText(dc, scale, rect{plot.right + f.px(8), plot.top - sh/2, r.right - pad, plot.top + sh/2 + 1}, font, f.col.subtext, dtSingleLine|dtVCenter|dtRight)
	drawText(dc, "0", rect{plot.right + f.px(8), plot.bottom - sh/2, r.right - pad, plot.bottom + sh/2 + 1}, font, f.col.subtext, dtSingleLine|dtVCenter|dtRight)
	now := rates[len(rates)-1].at
	width := float64(plot.right - plot.left)
	height := float64(plot.bottom-plot.top) - 1
	line := func(color uint32, v func(rate) float64) {
		type point struct{ x, y int32 }
		pts := make([]point, 0, len(rates))
		for _, p := range rates {
			age := now.Sub(p.at).Seconds() / trafficSpan.Seconds()
			if age > 1 {
				continue
			}
			pts = append(pts, point{int32(float64(plot.right) - age*width), int32(float64(plot.bottom) - 1 - v(p)/peak*height)})
		}
		if len(pts) == 1 {
			pts = append(pts, point{pts[0].x - 1, pts[0].y})
		}
		if len(pts) < 2 {
			return
		}
		pen, _, _ := procCreatePen.Call(psSolid, uintptr(f.px(2)), uintptr(color))
		old, _, _ := procSelectObject.Call(dc, pen)
		procPolyline.Call(dc, uintptr(unsafe.Pointer(&pts[0])), uintptr(len(pts)))
		procSelectObject.Call(dc, old)
		procDeleteObject.Call(pen)
	}
	line(sentColor, func(p rate) float64 { return p.tx })
	line(recvColor, func(p rate) float64 { return p.rx })
}

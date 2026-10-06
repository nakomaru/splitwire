package tray

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"

	"splitwire/internal/config"
	"splitwire/internal/ipc"
	"splitwire/internal/pmtu"
	"splitwire/internal/stats"
)

// The Details tab edits the tunnel's WireGuard settings, those of its
// interface or of one peer at a time. Save writes the fields that changed
// to the file, in place, keeping its comments and order.

// wmProbed tells the window that an MTU test finished.
const wmProbed = wmApp + 2

const (
	esPassword        = 0x0020
	emSetPasswordChar = 0x00CC
	// passwordChar hides the characters of a key.
	passwordChar = 0x25CF
)

// detailField is an edit box of the Details tab and the text of the
// settings it holds.
type detailField struct {
	label, c *control
	// key names the setting in config.DetailError; peer marks a peer's.
	key  string
	peer bool
	get  func(d *config.Details, peer int) *string
}

// detailsControls are the Details tab's controls and the settings being
// edited.
type detailsControls struct {
	segIface, segPeer                    *control
	peerStats, peerAdd, peerDel, pskNew  *control
	privShow, privNew, pubLabel, pub     *control
	copyPub, mtuTest, mtuNote            *control
	pskShow, private, note, revert, save *control

	fields                                        []*detailField
	priv, addrs, dns, port, mtu                   *detailField
	peerPub, psk, endpoint, keepalive, allowedIPs *detailField

	// forSel is the tunnel that orig and draft belong to; orig is its file's
	// settings and draft the window's.
	forSel      string
	orig, draft config.Details
	errs        []config.DetailError
	// peerPage shows peer number peer; the interface shows otherwise.
	peerPage bool
	peer     int
	probing  bool
	// noteFits reports that the MTU test's note fits under the MTU; the
	// line beside Save shows it otherwise.
	noteFits bool
	probed   chan probeResult
}

// probeResult is the outcome of an MTU test of a tunnel's path.
type probeResult struct {
	name string
	addr netip.Addr
	size int
	err  error
}

func (w *window) addDetails(f *form) {
	d := &w.det
	d.probed = make(chan probeResult, 1)
	d.segIface = f.add(&control{kind: kindButton, text: "Interface"})
	d.segPeer = f.add(&control{kind: kindButton, text: "Peer"})
	d.peerStats = f.add(&control{kind: kindLabel, color: labelSubtle})
	d.peerAdd = f.add(&control{kind: kindIcon, glyph: glyphAdd})
	f.setTip(d.peerAdd, "Add a peer")
	d.peerDel = f.add(&control{kind: kindIcon, glyph: glyphDelete})
	f.setTip(d.peerDel, "Remove this peer")
	field := func(label, key string, peer bool, style uint32, cue string, get func(*config.Details, int) *string) *detailField {
		df := &detailField{key: key, peer: peer, get: get}
		df.label = f.add(&control{kind: kindLabel, color: labelSubtle, text: label})
		df.c = &control{}
		if style&esMultiline != 0 {
			df.c.wrap = true
		}
		f.addEdit(df.c, style)
		if cue != "" {
			u, _ := windows.UTF16PtrFromString(cue)
			procSendMessageW.Call(df.c.hwnd, emSetCueBanner, 1, uintptr(unsafe.Pointer(u)))
		}
		d.fields = append(d.fields, df)
		return df
	}
	line := uint32(esAutoHScroll)
	d.priv = field("Private key", config.KeyPrivateKey, false, line|esPassword, "",
		func(c *config.Details, _ int) *string { return &c.PrivateKey })
	d.privShow = f.add(&control{kind: kindIcon, glyph: glyphView})
	f.setTip(d.privShow, "Show the key")
	d.privNew = f.add(&control{kind: kindIcon, glyph: glyphRefresh})
	f.setTip(d.privNew, "Generate a new key pair")
	d.pubLabel = f.add(&control{kind: kindLabel, color: labelSubtle, text: "Public key"})
	d.pub = f.add(&control{kind: kindLabel})
	d.copyPub = f.add(&control{kind: kindIcon, glyph: glyphCopy})
	f.setTip(d.copyPub, "Copy the public key")
	d.addrs = field("Addresses", config.KeyAddress, false, line, "None",
		func(c *config.Details, _ int) *string { return &c.Addresses })
	d.dns = field("DNS servers", config.KeyDNS, false, line, "None; the system's servers",
		func(c *config.Details, _ int) *string { return &c.DNS })
	d.port = field("Listen port", config.KeyListenPort, false, line|esNumber, "Random",
		func(c *config.Details, _ int) *string { return &c.ListenPort })
	d.mtu = field("MTU", config.KeyMTU, false, line|esNumber, "Automatic",
		func(c *config.Details, _ int) *string { return &c.MTU })
	d.mtuTest = f.add(&control{kind: kindButton, text: "Test"})
	f.setTip(d.mtuTest, "Pings the peer's endpoint with packets that may not be split, finds the largest "+
		"that arrives, and fills in the MTU that fits it.")
	d.mtuNote = f.add(&control{kind: kindLabel, color: labelSubtle, wrap: true})

	d.peerPub = field("Public key", config.KeyPublicKey, true, line, "",
		func(c *config.Details, p int) *string { return &c.Peers[p].PublicKey })
	d.psk = field("Preshared key", config.KeyPresharedKey, true, line|esPassword, "Optional",
		func(c *config.Details, p int) *string { return &c.Peers[p].PresharedKey })
	d.pskShow = f.add(&control{kind: kindIcon, glyph: glyphView})
	f.setTip(d.pskShow, "Show the key")
	d.pskNew = f.add(&control{kind: kindIcon, glyph: glyphRefresh})
	f.setTip(d.pskNew, "Generate a preshared key")
	d.endpoint = field("Endpoint", config.KeyEndpoint, true, line, "None; the peer connects",
		func(c *config.Details, p int) *string { return &c.Peers[p].Endpoint })
	d.keepalive = field("Keepalive", config.KeyKeepalive, true, line|esNumber, "Off",
		func(c *config.Details, p int) *string { return &c.Peers[p].Keepalive })
	f.setTip(d.keepalive.label, "Persistent keepalive: seconds between packets that keep a router's "+
		"NAT mapping open while the tunnel is idle. Off when empty.")
	d.allowedIPs = field("Allowed IPs", config.KeyAllowedIPs, true, esMultiline|esAutoVScroll|wsVScroll, "None",
		func(c *config.Details, p int) *string { return &c.Peers[p].AllowedIPs })
	d.private = f.add(&control{kind: kindCheck, text: "Exclude private IPs"})
	f.setTip(d.private, "Leaves the local network's private ranges and multicast out of the tunnel. "+
		"Private DNS servers stay in it.")

	d.note = f.add(&control{kind: kindLabel})
	d.revert = f.add(&control{kind: kindButton, text: "Revert"})
	d.save = f.add(&control{kind: kindButton, text: "Save", primary: true})
	for _, df := range []*detailField{d.port, d.mtu, d.keepalive} {
		procSendMessageW.Call(df.c.hwnd, emLimitText, 5, 0)
	}
}

// layoutDetails places the Details tab between y and bottom, with Save on
// the row at by.
func (w *window) layoutDetails(x0, x1, y, bottom, by int32) {
	f := w.f
	d := &w.det
	s := f.px
	bh := s(32)
	row := bh + s(8)
	lblW := s(112)
	icon := s(32)

	segW := max(f.buttonWidth(d.segIface), f.buttonWidth(d.segPeer))
	f.place(d.segIface, rect{x0, y, x0 + segW, y + bh})
	f.place(d.segPeer, rect{x0 + segW + s(4), y, x0 + 2*segW + s(4), y + bh})
	f.place(d.peerDel, rect{x1 - icon, y, x1, y + bh})
	f.place(d.peerAdd, rect{x1 - 2*icon - s(4), y, x1 - icon - s(4), y + bh})
	f.place(d.peerStats, rect{x0 + 2*segW + s(20), y, x1 - 2*icon - s(12), y + bh})
	y += row + s(6)
	top := y

	label := func(df *detailField, x int32) {
		lw, _ := f.measure(df.label.text, f.fonts[fontNormal])
		f.place(df.label, rect{x, y, x + lw, y + bh})
	}
	edit := func(df *detailField, right int32) {
		label(df, x0)
		f.place(df.c, rect{x0 + lblW, y, right, y + bh})
	}

	// The interface.
	edit(d.priv, x1-2*icon-s(8))
	f.place(d.privShow, rect{x1 - 2*icon - s(4), y, x1 - icon - s(4), y + bh})
	f.place(d.privNew, rect{x1 - icon, y, x1, y + bh})
	y += row
	f.place(d.pubLabel, rect{x0, y, x0 + lblW, y + bh})
	f.place(d.pub, rect{x0 + lblW + s(6), y, x1 - icon - s(4), y + bh})
	f.place(d.copyPub, rect{x1 - icon, y, x1, y + bh})
	y += row
	edit(d.addrs, x1)
	y += row
	edit(d.dns, x1)
	y += row
	numW := s(96)
	edit(d.port, x0+lblW+numW)
	mx := x0 + lblW + numW + s(24)
	label(d.mtu, mx)
	mx += d.mtu.label.r.right - d.mtu.label.r.left + s(12)
	f.place(d.mtu.c, rect{mx, y, mx + numW, y + bh})
	tw := f.buttonWidth(d.mtuTest)
	f.place(d.mtuTest, rect{mx + numW + s(8), y, mx + numW + s(8) + tw, y + bh})
	y += bh + s(6)
	nh := f.measureWrapped(d.mtuNote.text, f.fonts[fontNormal], x1-x0-lblW)
	f.place(d.mtuNote, rect{x0 + lblW, y, x1, y + nh})
	if fits := y+nh <= by-s(8); fits != d.noteFits {
		d.noteFits = fits
		defer w.checkDetails()
	}

	// A peer.
	y = top
	edit(d.peerPub, x1)
	y += row
	edit(d.psk, x1-2*icon-s(8))
	f.place(d.pskShow, rect{x1 - 2*icon - s(4), y, x1 - icon - s(4), y + bh})
	f.place(d.pskNew, rect{x1 - icon, y, x1, y + bh})
	y += row
	kw, _ := f.measure(d.keepalive.label.text, f.fonts[fontNormal])
	kx := x1 - numW - s(12) - kw
	edit(d.endpoint, kx-s(24))
	label(d.keepalive, kx)
	f.place(d.keepalive.c, rect{x1 - numW, y, x1, y + bh})
	y += row
	check := s(28) + s(6)
	h := clamp(bottom-y-check, bh, s(120))
	label(d.allowedIPs, x0)
	f.place(d.allowedIPs.c, rect{x0 + lblW, y, x1, y + h})
	y += h + s(6)
	f.place(d.private, rect{x0 + lblW, y, x0 + lblW + f.toggleWidth(d.private), y + s(28)})

	sw := f.buttonWidth(d.save)
	vw := f.buttonWidth(d.revert)
	f.place(d.save, rect{x1 - sw, by, x1, by + bh})
	f.place(d.revert, rect{x1 - sw - s(8) - vw, by, x1 - sw - s(8), by + bh})
	f.place(d.note, rect{x0, by, x1 - sw - vw - s(24), by + bh})
}

// showDetails shows the Details tab's controls of the page in view, or
// hides them all.
func (w *window) showDetails(on bool) {
	f := w.f
	d := &w.det
	iface := on && !d.peerPage
	peer := on && d.peerPage && len(d.draft.Peers) > 0
	for _, df := range d.fields {
		show := iface
		if df.peer {
			show = peer
		}
		f.show(df.label, show)
		f.show(df.c, show)
	}
	for _, c := range []*control{d.privShow, d.privNew, d.pubLabel, d.pub, d.copyPub, d.mtuTest} {
		f.show(c, iface)
	}
	f.show(d.mtuNote, iface && d.noteFits)
	for _, c := range []*control{d.pskShow, d.pskNew, d.peerDel, d.peerStats} {
		f.show(c, peer)
	}
	applies := false
	if peer {
		applies, _ = config.PrivateIPs(d.draft.Peers[d.peer].AllowedIPs)
	}
	f.show(d.private, applies)
	for _, c := range []*control{d.segIface, d.segPeer, d.peerAdd, d.note, d.revert, d.save} {
		f.show(c, on)
	}
}

// loadDetails takes in the settings of the tunnel's file.
func (w *window) loadDetails() {
	d := &w.det
	if d.forSel != w.sel {
		d.forSel, d.peerPage, d.peer = w.sel, false, 0
		w.f.setText(d.mtuNote, "")
	}
	d.orig = config.Details{}
	if w.cfg != nil {
		d.orig = config.DetailsOf(w.cfg)
	}
	d.draft = d.orig.Clone()
	d.peer = min(d.peer, max(len(d.draft.Peers)-1, 0))
	w.fillDetails()
	w.checkDetails()
}

// fillDetails puts the draft into the edit boxes.
func (w *window) fillDetails() {
	d := &w.det
	w.loading = true
	for _, df := range d.fields {
		text := ""
		if !df.peer || d.peer < len(d.draft.Peers) {
			text = *df.get(&d.draft, d.peer)
		}
		w.f.setText(df.c, text)
	}
	w.loading = false
}

// setField changes a field's text in the draft and its edit box.
func (w *window) setField(df *detailField, text string) {
	*df.get(&w.det.draft, w.det.peer) = text
	w.loading = true
	w.f.setText(df.c, text)
	w.loading = false
	w.checkDetails()
}

func (w *window) detailsDirty() bool {
	d := &w.det
	return d.forSel != "" && d.forSel == w.sel && !d.draft.Equal(d.orig)
}

// updateDetails shows the peer selector, and reports whether the layout
// needs to follow.
func (w *window) updateDetails() bool {
	f := w.f
	d := &w.det
	n := len(d.draft.Peers)
	text := "Peer"
	if n > 1 {
		text = fmt.Sprintf("Peer %d of %d", d.peer+1, n)
	}
	changed := d.segPeer.text != text || d.segPeer.menu != (n > 1)
	d.segPeer.menu = n > 1
	f.setText(d.segPeer, text)
	f.setOn(d.segIface, !d.peerPage)
	f.setOn(d.segPeer, d.peerPage)
	f.enable(d.segPeer, n > 0)
	f.enable(d.mtuTest, !d.probing)
	live := w.peerStats()
	f.setText(d.peerStats, live)
	if d.peerStats.tip != live {
		f.setTip(d.peerStats, live)
	}
	return changed
}

// peerStats describes the live state of the peer in view, or is "" while
// the tunnel is down.
func (w *window) peerStats() string {
	d := &w.det
	t := w.tunnel()
	if t == nil || t.State != ipc.StateUp || d.peer >= len(d.draft.Peers) {
		return ""
	}
	key := strings.TrimSpace(d.draft.Peers[d.peer].PublicKey)
	for _, p := range t.Peers {
		if p.PublicKey == key {
			return "Handshake " + stats.Ago(p.LastHandshake) + " \u00B7 " + stats.Bytes(p.RxBytes) + " received, " +
				stats.Bytes(p.TxBytes) + " sent"
		}
	}
	return "Not connected"
}

// checkDetails checks the draft and shows its problems.
func (w *window) checkDetails() {
	f := w.f
	d := &w.det
	_, d.errs = d.draft.Clean()
	// Problems on the page in view come first.
	slices.SortStableFunc(d.errs, func(a, b config.DetailError) int {
		here := func(e config.DetailError) int {
			if d.peerPage == (e.Peer >= 0) && (!d.peerPage || e.Peer == d.peer) {
				return 0
			}
			return 1
		}
		return here(a) - here(b)
	})
	for _, df := range d.fields {
		warn := false
		for _, e := range d.errs {
			warn = warn || e.Key == df.key && (df.peer && e.Peer == d.peer || !df.peer && e.Peer < 0)
		}
		if df.c.warn != warn {
			df.c.warn = warn
			f.invalidate(df.c)
		}
	}

	pub := "Enter a valid private key."
	if k, err := conf.NewPrivateKeyFromString(strings.TrimSpace(d.draft.PrivateKey)); err == nil {
		pub = k.Public().String()
	}
	f.setText(d.pub, pub)
	f.enable(d.copyPub, !strings.HasSuffix(pub, "."))
	if d.peer < len(d.draft.Peers) {
		_, excluded := config.PrivateIPs(d.draft.Peers[d.peer].AllowedIPs)
		f.setOn(d.private, excluded)
	}
	if w.tab == tabDetails && w.sel != "" && w.cfg != nil {
		w.showDetails(true)
	}

	dirty := !d.draft.Equal(d.orig)
	note := ""
	switch {
	case len(d.errs) > 0:
		d.note.color = labelError
		note = w.detailError(d.errs[0])
	case d.mtuNote.text != "" && !d.noteFits:
		d.note.color = d.mtuNote.color
		note = d.mtuNote.text
	case dirty:
		d.note.color = labelSuccess
		note = "No problems found. Save to keep the changes."
	case w.cfg != nil && len(w.cfg.Scripts()) > 0:
		d.note.color = labelCaution
		note = scriptsNote(w.cfg)
	}
	f.setText(d.note, note)
	if d.note.tip != note {
		f.setTip(d.note, note)
	}
	f.enable(d.save, dirty && len(d.errs) == 0)
	f.enable(d.revert, dirty)
}

// detailError describes a problem with a field, by the field's label.
func (w *window) detailError(e config.DetailError) string {
	d := &w.det
	name := e.Key
	for _, df := range d.fields {
		if df.key == e.Key {
			name = df.label.text
		}
	}
	if e.Peer >= 0 {
		lower := strings.ToLower(name[:1]) + name[1:]
		name = "Peer's " + lower
		if len(d.draft.Peers) > 1 {
			name = fmt.Sprintf("Peer %d's %s", e.Peer+1, lower)
		}
	}
	return name + ": " + e.Err.Error()
}

// saveDetails writes the changed settings to the file, and reports success.
func (w *window) saveDetails() bool {
	d := &w.det
	clean, errs := d.draft.Clean()
	if len(errs) > 0 {
		messageBox(w.f.hwnd, "Fix the problem before saving:\n\n"+w.detailError(errs[0]), windows.MB_ICONWARNING)
		return false
	}
	fail := func(err error) bool {
		messageBox(w.f.hwnd, "Could not save "+w.sel+":\n\n"+err.Error(), windows.MB_ICONERROR)
		return false
	}
	b, err := os.ReadFile(w.path)
	if err != nil {
		return fail(err)
	}
	if c, err := config.Parse(string(b), w.sel); err == nil && len(c.WG.Peers) != len(d.orig.Peers) {
		return fail(fmt.Errorf("its peers changed on disk; revert to see them"))
	}
	text := config.ApplyDetails(string(b), d.orig, clean)
	if _, err := config.Parse(text, w.sel); err != nil {
		return fail(err)
	}
	if err := os.WriteFile(w.path, []byte(text), 0o600); err != nil {
		return fail(err)
	}
	w.load()
	w.update()
	return true
}

// detailsCommand handles the Details tab's controls, and reports whether c
// is one of them.
func (w *window) detailsCommand(c *control, code uint16) bool {
	f := w.f
	d := &w.det
	for _, df := range d.fields {
		if c == df.c {
			if code == enChange && !w.loading && (!df.peer || d.peer < len(d.draft.Peers)) {
				*df.get(&d.draft, d.peer) = windowText(c.hwnd)
				w.checkDetails()
			}
			return true
		}
	}
	if code != bnClicked {
		return false
	}
	switch c {
	case d.segIface:
		w.detailsPage(false, d.peer)
	case d.segPeer:
		if !d.peerPage || len(d.draft.Peers) < 2 {
			w.detailsPage(true, d.peer)
			break
		}
		var items []menuItem
		for i, p := range d.draft.Peers {
			text := fmt.Sprintf("Peer %d", i+1)
			if ep := strings.TrimSpace(p.Endpoint); ep != "" {
				text += " · " + ep
			}
			items = append(items, menuItem{text: text, check: i == d.peer, run: func() { w.detailsPage(true, i) }})
		}
		f.popupUnder(d.segPeer, items)
	case d.privShow:
		w.toggleShown(d.privShow, d.priv)
	case d.pskShow:
		w.toggleShown(d.pskShow, d.psk)
	case d.privNew:
		w.newPrivateKey()
	case d.pskNew:
		w.newPresharedKey()
	case d.peerAdd:
		d.draft.Peers = append(d.draft.Peers, config.PeerDetails{From: -1})
		w.detailsPage(true, len(d.draft.Peers)-1)
		procSetFocus.Call(d.peerPub.c.hwnd)
	case d.peerDel:
		w.removePeer()
	case d.copyPub:
		if f.enabled(d.copyPub) {
			w.copy(d.pub.text)
		}
	case d.mtuTest:
		w.testMTU()
	case d.private:
		if d.peer < len(d.draft.Peers) {
			ips, err := config.ExcludePrivateIPs(d.draft.Peers[d.peer].AllowedIPs, d.draft.DNS, !d.private.on)
			if err == nil {
				w.setField(d.allowedIPs, ips)
			}
		}
	case d.revert:
		w.loadDetails()
		w.update()
	case d.save:
		w.saveDetails()
	default:
		return false
	}
	return true
}

// detailsPage shows the interface, or peer number peer.
func (w *window) detailsPage(peerPage bool, peer int) {
	d := &w.det
	d.peerPage, d.peer = peerPage, peer
	w.fillDetails()
	w.checkDetails()
	w.update()
}

// toggleShown shows or hides the characters of a key's edit box.
func (w *window) toggleShown(icon *control, df *detailField) {
	hidden := icon.glyph == glyphView
	ch, glyph, tip := uintptr(0), rune(glyphHide), "Hide the key"
	if !hidden {
		ch, glyph, tip = passwordChar, glyphView, "Show the key"
	}
	procSendMessageW.Call(df.c.hwnd, emSetPasswordChar, ch, 0)
	procInvalidateRect.Call(df.c.hwnd, 0, 1)
	icon.glyph = glyph
	w.f.setTip(icon, tip)
	w.f.invalidate(icon)
}

func (w *window) newPrivateKey() {
	if messageBox(w.f.hwnd, "Generate a new private key for "+w.sel+"?\n\n"+
		"Its public key changes too, and its server accepts it only once the server has the new public key. "+
		"Saving discards the current key for good.",
		windows.MB_YESNO|windows.MB_ICONWARNING|windows.MB_DEFBUTTON2) != idYes {
		return
	}
	k, err := conf.NewPrivateKey()
	if err != nil {
		messageBox(w.f.hwnd, "Could not generate a key:\n\n"+err.Error(), windows.MB_ICONERROR)
		return
	}
	w.setField(w.det.priv, k.String())
}

// newPresharedKey fills in a new preshared key, asking first when it
// replaces one.
func (w *window) newPresharedKey() {
	d := &w.det
	if d.peer >= len(d.draft.Peers) {
		return
	}
	if strings.TrimSpace(d.draft.Peers[d.peer].PresharedKey) != "" && messageBox(w.f.hwnd,
		"Replace the preshared key?\n\nThe peer accepts the tunnel only once it has the same key.",
		windows.MB_YESNO|windows.MB_ICONWARNING|windows.MB_DEFBUTTON2) != idYes {
		return
	}
	k, err := conf.NewPresharedKey()
	if err != nil {
		messageBox(w.f.hwnd, "Could not generate a key:\n\n"+err.Error(), windows.MB_ICONERROR)
		return
	}
	w.setField(d.psk, k.String())
}

// removePeer drops the peer in view from the draft, after asking.
func (w *window) removePeer() {
	d := &w.det
	if d.peer >= len(d.draft.Peers) {
		return
	}
	what := fmt.Sprintf("peer %d", d.peer+1)
	if ep := strings.TrimSpace(d.draft.Peers[d.peer].Endpoint); ep != "" {
		what += " (" + ep + ")"
	}
	if messageBox(w.f.hwnd, "Remove "+what+" from "+w.sel+"? It goes when you save.",
		windows.MB_YESNO|windows.MB_ICONWARNING|windows.MB_DEFBUTTON2) != idYes {
		return
	}
	d.draft.Peers = slices.Delete(d.draft.Peers, d.peer, d.peer+1)
	n := len(d.draft.Peers)
	w.detailsPage(n > 0, min(d.peer, max(n-1, 0)))
}

// testMTU measures the path to the first peer's endpoint on another
// thread, which posts wmProbed when done.
func (w *window) testMTU() {
	d := &w.det
	f := w.f
	host := ""
	for _, p := range d.draft.Peers {
		ep := strings.TrimSpace(p.Endpoint)
		if i := strings.LastIndexByte(ep, ':'); i > 0 {
			host = strings.Trim(ep[:i], "[]")
			break
		}
	}
	if host == "" {
		w.mtuNote("Testing needs a peer with an endpoint.", labelSubtle)
		return
	}
	d.probing = true
	f.enable(d.mtuTest, false)
	w.mtuNote("Testing the path to "+host+"...", labelSubtle)
	name, hwnd := w.sel, w.f.hwnd
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		r := probeResult{name: name}
		r.addr, r.err = endpointAddr(ctx, host)
		if r.err == nil {
			r.size, r.err = pmtu.Probe(ctx, r.addr)
		}
		d.probed <- r
		postMessage(hwnd, wmProbed)
	}()
}

// endpointAddr resolves an endpoint's host as WireGuard does: its first
// IPv4 address, or its first IPv6 address without one.
func endpointAddr(ctx context.Context, host string) (netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("could not look up %s", host)
	}
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return addrs[0], nil
}

// probed shows the outcome of an MTU test, and fills in the MTU it found.
func (w *window) probed() {
	d := &w.det
	var r probeResult
	select {
	case r = <-d.probed:
	default:
		return
	}
	d.probing = false
	w.f.enable(d.mtuTest, true)
	if r.name != w.sel {
		return
	}
	if r.err != nil {
		w.mtuNote("The test failed: "+r.err.Error()+".", labelError)
		return
	}
	mtu := r.size - pmtu.Overhead(r.addr)
	w.setField(d.mtu, strconv.Itoa(mtu))
	w.mtuNote(fmt.Sprintf("The path to %s carries packets of up to %d bytes, so an MTU of %d fits.",
		r.addr, r.size, mtu), labelSubtle)
}

// mtuNote shows the state of the MTU test.
func (w *window) mtuNote(text string, color int) {
	w.det.mtuNote.color = color
	w.f.setText(w.det.mtuNote, text)
	w.relayout()
	w.checkDetails()
}

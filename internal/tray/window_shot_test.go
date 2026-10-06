package tray

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/conf"

	"splitwire/internal/config"
	"splitwire/internal/ipc"
	"splitwire/internal/settings"
	"splitwire/internal/stats"
	"splitwire/internal/userconf"
)

var (
	procPrintWindow                   = user32.NewProc("PrintWindow")
	procGetDIBits                     = gdi32.NewProc("GetDIBits")
	procPeekMessageW                  = user32.NewProc("PeekMessageW")
	procSetProcessDpiAwarenessContext = user32.NewProc("SetProcessDpiAwarenessContext")
)

// TestWindowShots renders the window off screen with made-up tunnels and
// saves PNG files to $SPLITWIRE_SHOTS, for looking at the layout.
func TestWindowShots(t *testing.T) {
	out := os.Getenv("SPLITWIRE_SHOTS")
	if out == "" {
		t.Skip("set SPLITWIRE_SHOTS to a folder for the screenshots")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	procSetProcessDpiAwarenessContext.Call(^uintptr(3)) // per monitor v2
	useManifest(t)
	userconf.UseDir(t.TempDir())
	key := func() string {
		k, err := conf.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		return k.String()
	}
	write := func(name, splitwire string) {
		text := "[Interface]\nPrivateKey = " + key() + "\nAddress = 10.64.0.2/32, fd00::2/128\nDNS = 10.64.0.1\n\n" +
			"[Peer]\nPublicKey = " + key() + "\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 203.0.113.9:51820\n\n" + splitwire
		dir, _ := userconf.Dir()
		if err := os.WriteFile(filepath.Join(dir, name+".conf"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("Office", "[SplitWire]\nMode = include\nApp = C:\\Windows\\System32\\curl.exe\n"+
		"App = C:\\Program Files\\Mozilla Firefox\\firefox.exe\nApp = %LOCALAPPDATA%\\Discord\\app-*\\Discord.exe\n"+
		"App = C:\\Games\\Missing\\game.exe\n"+config.ExampleSection)
	write("WARP", "[SplitWire]\nProxy = 1080\n"+config.ExampleSection)
	write("home", config.ExampleSection)
	dir, _ := userconf.Dir()
	os.WriteFile(filepath.Join(dir, "lab.conf"), []byte("[Interface]\nPrivateKey = "+key()+
		"\nAddress = 10.9.0.2/32\nDNS = 10.9.0.1, lab.example\n\n[Peer]\nPublicKey = "+key()+
		"\nAllowedIPs = 10.9.0.0/16\nEndpoint = 198.51.100.4:51820\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "broken.conf"), []byte("[Interface]\nPrivateKey = nope\n"), 0o600)

	a := newApp()
	a.scanTunnels()
	now := time.Now()
	office := ipc.Tunnel{Name: "Office", As: ipc.AsSplit, State: ipc.StateUp, Mode: "include", Apps: 3,
		ConfigHash: a.files["Office"].hash, Since: now.Add(-47 * time.Minute)}
	warpT := ipc.Tunnel{Name: "WARP", As: ipc.AsProxy, State: ipc.StateUp, Listen: "127.0.0.1:1080",
		ConfigHash: a.files["WARP"].hash, Since: now.Add(-3 * time.Hour)}
	a.link = linkConnected
	var rx, tx uint64 = 900 << 20, 40 << 20
	for i := 90; i >= 0; i-- {
		at := now.Add(-time.Duration(i) * 2 * time.Second)
		rx += uint64(400e3 + 300e3*math.Sin(float64(i)/7))
		tx += uint64(40e3 + 30e3*math.Cos(float64(i)/5))
		for _, tn := range []*ipc.Tunnel{&office, &warpT} {
			tn.Peers = []stats.Peer{{LastHandshake: now.Add(-12 * time.Second), RxBytes: rx, TxBytes: tx}}
		}
		a.status = ipc.Status{Tunnels: []ipc.Tunnel{office, warpT}}
		tr := a.traffic["Office"]
		if tr == nil {
			tr = &traffic{since: office.Since}
			a.traffic["Office"] = tr
		}
		tr.samples = append(tr.samples, sample{at, rx, tx})
	}

	for _, theme := range []struct {
		name string
		mode int
	}{{"dark", 1}, {"light", 2}} {
		testTheme = theme.mode
		Version = "0.4.3"
		w := newWindow(a)
		offscreen(w.f.hwnd)
		w.pick(w.rowOf("Office"))
		shot(t, w.f.hwnd, filepath.Join(out, theme.name+"-vpn.png"))
		w.showTab(tabProxy)
		shot(t, w.f.hwnd, filepath.Join(out, theme.name+"-proxy.png"))
		w.showTab(tabDetails)
		shot(t, w.f.hwnd, filepath.Join(out, theme.name+"-details.png"))
		w.showTab(tabText)
		shot(t, w.f.hwnd, filepath.Join(out, theme.name+"-text.png"))
		w.f.setText(w.editor, strings.Replace(windowText(w.editor.hwnd), "[Interface]", "[Interface]\r\nMTU = nope", 1))
		shot(t, w.f.hwnd, filepath.Join(out, theme.name+"-text-error.png"))
		w.load()
		w.showTab(tabVPN)
		// Switching Office off and on again, captured as painted.
		starting := office
		starting.State, starting.Peers = ipc.StateStarting, nil
		for i, tunnels := range [][]ipc.Tunnel{{warpT}, {starting, warpT}, {office, warpT}, {warpT}} {
			a.status = ipc.Status{Tunnels: tunnels}
			w.refresh()
			capture(t, w.f.hwnd, filepath.Join(out, fmt.Sprintf("%s-switch-%d.png", theme.name, i)))
		}
		w.pick(w.rowOf("WARP")) // a proxy in full mode
		shot(t, w.f.hwnd, filepath.Join(out, theme.name+"-warp-vpn.png"))
		w.showTab(tabProxy)
		shot(t, w.f.hwnd, filepath.Join(out, theme.name+"-warp-proxy.png"))
		w.pick(w.rowOf("broken"))
		shot(t, w.f.hwnd, filepath.Join(out, theme.name+"-broken.png"))
		homeT := ipc.Tunnel{Name: "home", As: ipc.AsVPN, State: ipc.StateUp, ConfigHash: a.files["home"].hash, Since: now}
		labT := ipc.Tunnel{Name: "lab", As: ipc.AsVPN, State: ipc.StateUp, ConfigHash: a.files["lab"].hash, Since: now}
		a.status = ipc.Status{Tunnels: []ipc.Tunnel{office, warpT, homeT, labT}, Settings: settings.Settings{
			KillSwitch: true, StrictDNS: true, Direct: []string{"10.9.4.0/24", "vpn.office.example"}}}
		w.refresh()
		w.pick(overviewRow)
		shot(t, w.f.hwnd, filepath.Join(out, theme.name+"-overview.png"))
		a.status = ipc.Status{Tunnels: []ipc.Tunnel{office, warpT}}
		p := newPicker(w.f.hwnd, "Office", a.files["Office"].cfg.Apps)
		offscreen(p.f.hwnd)
		shot(t, p.f.hwnd, filepath.Join(out, theme.name+"-picker.png"))
		procDestroyWindow.Call(p.f.hwnd)
		w.f.destroyed = nil
		procDestroyWindow.Call(w.f.hwnd)
	}
	testTheme = 0
}

// useManifest activates the app's manifest on the thread, for the common
// controls it asks for.
func useManifest(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "winres", "splitwire.manifest"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := windows.UTF16PtrFromString(path)
	ctx := struct {
		size, flags                uint32
		source                     *uint16
		arch, lang                 uint16
		dir, resource, application *uint16
		module                     uintptr
	}{source: p}
	ctx.size = uint32(unsafe.Sizeof(ctx))
	k := windows.NewLazySystemDLL("kernel32.dll")
	h, _, err := k.NewProc("CreateActCtxW").Call(uintptr(unsafe.Pointer(&ctx)))
	if h == ^uintptr(0) {
		t.Fatalf("CreateActCtx: %v", err)
	}
	var cookie uintptr
	k.NewProc("ActivateActCtx").Call(h, uintptr(unsafe.Pointer(&cookie)))
}

// offscreen puts a window off screen, out of the taskbar, without activating it.
func offscreen(hwnd uintptr) {
	const gwlExStyle = ^uintptr(19) // -20
	const wsExToolWindow = 0x80
	ex, _, _ := procGetWindowLongPtrW.Call(hwnd, gwlExStyle)
	procSetWindowLongPtrW.Call(hwnd, gwlExStyle, ex|wsExToolWindow)
	var r rect
	procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	procSetWindowPos.Call(hwnd, 0, ^uintptr(31999), 0, 0, 0, swpNoSize|swpNoZOrder|swpNoActivate)
	procShowWindow.Call(hwnd, swShowNA)
}

// pump handles the queued messages, so the windows paint.
func pump() {
	var m [48]byte
	const pmRemove = 1
	for i := 0; i < 50; i++ {
		for {
			r, _, _ := procPeekMessageW.Call(uintptr(unsafe.Pointer(&m[0])), 0, 0, 0, pmRemove)
			if r == 0 {
				break
			}
			procTranslateMessage.Call(uintptr(unsafe.Pointer(&m[0])))
			procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m[0])))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// shot repaints the window and saves its image as a PNG file.
func shot(t *testing.T, hwnd uintptr, path string) {
	const rdwUpdateNow = 0x0100
	procRedrawWindow.Call(hwnd, 0, 0, rdwInvalidate|rdwErase|rdwAllChildren|rdwFrame|rdwUpdateNow)
	capture(t, hwnd, path)
}

// capture saves the window's image as a PNG file once it handles its
// queued messages.
func capture(t *testing.T, hwnd uintptr, path string) {
	pump()
	var r rect
	procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&r)))
	w, h := r.right-r.left, r.bottom-r.top
	screen, _, _ := procGetDC.Call(0)
	defer procReleaseDC.Call(0, screen)
	dc, _, _ := procCreateCompatibleDC.Call(screen)
	defer procDeleteDC.Call(dc)
	bmp, _, _ := procCreateCompatibleBitmap.Call(screen, uintptr(w), uintptr(h))
	defer procDeleteObject.Call(bmp)
	old, _, _ := procSelectObject.Call(dc, bmp)
	const pwRenderFullContent = 2
	procPrintWindow.Call(hwnd, dc, pwRenderFullContent)
	procSelectObject.Call(dc, old)
	bi := struct {
		size                 uint32
		width, height        int32
		planes, bitCount     uint16
		compression, sizeImg uint32
		xppm, yppm           int32
		clrUsed, clrImp      uint32
	}{width: w, height: -h, planes: 1, bitCount: 32}
	bi.size = uint32(unsafe.Sizeof(bi))
	buf := make([]byte, w*h*4)
	procGetDIBits.Call(dc, bmp, 0, uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bi)), 0)
	img := image.NewRGBA(image.Rect(0, 0, int(w), int(h)))
	for i := 0; i < len(buf); i += 4 {
		img.Set(i/4%int(w), i/4/int(w), color.RGBA{buf[i+2], buf[i+1], buf[i], 0xff})
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

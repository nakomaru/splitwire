// Command splitwire is a VPN client for Windows with per-app split
// tunneling. Started without arguments from Explorer, it is the
// notification area app; from a shell, it is the command line.
package main

//go:generate go run ./tools/mkicon winres/icon.ico
//go:generate go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --arch amd64,arm64 --out rsrc

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"splitwire/internal/bootstrap"
	"splitwire/internal/config"
	"splitwire/internal/console"
	"splitwire/internal/elevate"
	"splitwire/internal/engine"
	"splitwire/internal/firewall"
	"splitwire/internal/ipc"
	"splitwire/internal/logx"
	"splitwire/internal/manager"
	"splitwire/internal/netcfg"
	"splitwire/internal/proxy"
	"splitwire/internal/service"
	"splitwire/internal/shortcut"
	"splitwire/internal/stats"
	"splitwire/internal/stdriver"
	"splitwire/internal/tray"
	"splitwire/internal/update"
	"splitwire/internal/userconf"
	"splitwire/internal/warp"
	"splitwire/internal/wgimport"
)

const version = "0.4.1"

const usage = `SplitWire ` + version + ` - a VPN client with per-app split tunneling

Usage:
  splitwire                             Open the app and its window (also by double-clicking)
  splitwire import [--force] [name...]  Copy tunnels from the WireGuard app
  splitwire up <tunnel>                 Run a tunnel in this console until Ctrl+C
  splitwire proxy <tunnel>              Run a tunnel as a local proxy in this console until Ctrl+C
  splitwire warp [name]                 Register a free Cloudflare WARP device as a new tunnel
  splitwire check <tunnel>              Validate a configuration and show its effect
  splitwire apps [filter]               List running programs with their paths
  splitwire direct [add|remove <entry>...]
                                        List, add or remove Always direct address ranges,
                                        addresses and host names, which no tunnel carries
  splitwire install <tunnel>            Install a tunnel as a service that starts at boot
  splitwire uninstall <name>            Stop and remove an installed tunnel
  splitwire start <name>                Start an installed tunnel
  splitwire stop <name>                 Stop an installed tunnel
  splitwire status [name]               Show tunnels, the driver and peer statistics
  splitwire bootstrap                   Install wireguard.dll, the WireGuardNT and split tunnel drivers
  splitwire update                      Install the newest signed release over the installed copy
  splitwire manager install [options]   Set up the service the notification area app uses:
                                        --boot or --no-boot turns reconnecting tunnels at boot on
                                        or off, --wireguard-driver and
                                        --split-tunnel-driver install those drivers now, --import
                                        imports from the WireGuard app, --user=SID allows that
                                        user instead of the current one; "manager leave" removes
                                        a user again, "manager uninstall" removes the service
  splitwire cleanup [options]           Uninstall everything; --configs also deletes your tunnel
                                        files, --keep-wireguardnt keeps the WireGuardNT driver
  splitwire version

A <tunnel> is a name, for %APPDATA%\splitwire\<name>.conf, or a path to a .conf file.
"up" imports a named tunnel from the WireGuard app when the file does not exist yet.
Commands that change the system ask for administrator rights.
`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		switch console.Current() {
		case console.None:
			args = []string{tray.Command}
		case console.Own:
			console.Free()
			args = []string{tray.Command}
		}
	}
	if len(args) > 0 && args[0] == tray.Command {
		tray.Version = version
		runTray(args[1:])
		return
	}
	hold, holdOnError := false, false
	if len(args) > 0 && args[0] == elevate.HoldFlag {
		hold = true
		args = args[1:]
	} else if len(args) > 0 && args[0] == elevate.HoldOnErrorFlag {
		holdOnError = true
		args = args[1:]
	}
	if hold || holdOnError {
		console.Ensure()
	}
	err := run(args)
	if err != nil {
		log.Printf("Error: %v", err)
	}
	if hold || (holdOnError && err != nil) {
		elevate.WaitForEnter()
	}
	if err != nil {
		os.Exit(1)
	}
}

// runTray runs the notification area app, detached from any shell so the
// shell gets its prompt back.
func runTray(args []string) {
	if console.Current() == console.Shared {
		self, err := os.Executable()
		if err == nil {
			cmd := exec.Command(self, append([]string{tray.Command}, args...)...)
			cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
			err = cmd.Start()
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	console.Free()
	if err := tray.Run(args); err != nil {
		text, _ := windows.UTF16PtrFromString("SplitWire could not start:\n\n" + err.Error())
		caption, _ := windows.UTF16PtrFromString("SplitWire")
		windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONERROR)
		os.Exit(1)
	}
}

// Flags of manager install and cleanup.
var (
	installFlags = []string{"--boot", "--no-boot", "--wireguard-driver", "--split-tunnel-driver", "--import", "--user="}
	cleanupFlags = []string{"--configs", "--keep-wireguardnt"}
)

// onlyFlags reports whether every argument is one of allowed. An allowed
// flag ending in = takes a value after it.
func onlyFlags(args []string, allowed ...string) bool {
	for _, a := range args {
		known := false
		for _, f := range allowed {
			if a == f || (strings.HasSuffix(f, "=") && strings.HasPrefix(a, f)) {
				known = true
			}
		}
		if !known {
			return false
		}
	}
	return true
}

// flagValue is the value of the flag prefix, such as --user=, or "".
func flagValue(args []string, prefix string) string {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, prefix); ok {
			return v
		}
	}
	return ""
}

// choice reads a pair of opposite flags.
func choice(args []string, on, off string) manager.Choice {
	switch {
	case hasFlag(args, on):
		return manager.On
	case hasFlag(args, off):
		return manager.Off
	}
	return manager.Keep
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func needArg(args []string, what string) (string, error) {
	if len(args) != 2 {
		return "", fmt.Errorf("usage: splitwire %s %s", args[0], what)
	}
	return args[1], nil
}

// requireAdmin relaunches the command elevated when needed. It reports true
// when the caller should stop because an elevated copy took over.
func requireAdmin(args []string) (bool, error) {
	if elevate.IsElevated() {
		return false, nil
	}
	log.Printf("Requesting administrator rights; the command continues in a new window")
	return true, elevate.Relaunch(args, true)
}

// absArg resolves a tunnel argument to its configuration path, so an
// elevated relaunch finds the same file.
func absArg(args []string) []string {
	out := append([]string(nil), args...)
	if len(out) == 2 && userconf.IsPath(out[1]) {
		if p, err := userconf.Resolve(out[1]); err == nil {
			out[1] = p
		}
	}
	return out
}

// existingConf resolves a tunnel argument to a configuration file that exists.
func existingConf(arg string) (string, error) {
	path, err := userconf.Resolve(arg)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) && !userconf.IsPath(arg) {
			return "", fmt.Errorf("no configuration %s; run `splitwire import %s` to copy it from the WireGuard app", path, arg)
		}
		return "", err
	}
	return path, nil
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	if args[0] == service.RunCommand {
		if len(args) != 2 {
			return errors.New("service-run needs a configuration path")
		}
		return service.Run(args[1])
	}
	if args[0] == manager.RunCommand {
		legacyUser := ""
		if len(args) > 1 {
			legacyUser = args[1]
		}
		return manager.Run(legacyUser)
	}
	if args[0] == wgimport.HelperCommand {
		if len(args) < 3 {
			return errors.New("helper needs an output folder and tunnel names")
		}
		return wgimport.RunHelper(args[1], args[2:])
	}
	if _, err := logx.Setup(""); err != nil {
		return err
	}

	switch args[0] {
	case "version", "-v", "--version":
		fmt.Println("splitwire", version)
		return nil
	case "help", "-h", "--help", "/?":
		fmt.Print(usage)
		return nil
	case "check":
		arg, err := needArg(args, "<tunnel>")
		if err != nil {
			return err
		}
		path, err := existingConf(arg)
		if err != nil {
			return err
		}
		return check(path)
	case "warp":
		if len(args) > 2 {
			return errors.New("usage: splitwire warp [name]")
		}
		name := "WARP"
		if len(args) == 2 {
			name = args[1]
		}
		return createWARP(name)
	case "proxy":
		arg, err := needArg(args, "<tunnel>")
		if err != nil {
			return err
		}
		path, err := existingConf(arg)
		if err != nil {
			return err
		}
		return runProxy(path)
	case "apps":
		filter := ""
		if len(args) > 1 {
			filter = strings.Join(args[1:], " ")
		}
		return apps(filter)
	case "direct":
		return direct(args[1:])
	}

	switch args[0] {
	case "up", "install":
		if _, err := needArg(args, "<tunnel>"); err != nil {
			return err
		}
		args = absArg(args)
	case "import":
	case "uninstall", "start", "stop":
		if _, err := needArg(args, "<name>"); err != nil {
			return err
		}
	case "manager":
		ok := len(args) >= 2
		if ok {
			switch args[1] {
			case "install":
				ok = onlyFlags(args[2:], installFlags...)
			case "leave":
				ok = onlyFlags(args[2:], "--user=")
			case "uninstall":
				ok = len(args) == 2
			default:
				ok = false
			}
		}
		if !ok {
			flags := strings.ReplaceAll(strings.Join(installFlags, "] ["), "--user=", "--user=SID")
			return errors.New("usage: splitwire manager install [" + flags + "] | leave [--user=SID] | uninstall")
		}
	case "cleanup":
		if !onlyFlags(args[1:], cleanupFlags...) {
			return errors.New("usage: splitwire cleanup [" + strings.Join(cleanupFlags, "] [") + "]")
		}
	case "update":
		if !onlyFlags(args[1:], "--user=") {
			return errors.New("usage: splitwire update [--user=SID]")
		}
		// The user is recorded before elevating, which can switch accounts.
		if flagValue(args[1:], "--user=") == "" {
			sid, err := manager.CurrentUser()
			if err != nil {
				return err
			}
			args = append(args, "--user="+sid)
		}
	case "status", "bootstrap":
	default:
		return fmt.Errorf("unknown command %q; run splitwire help", args[0])
	}
	if relaunched, err := requireAdmin(args); relaunched || err != nil {
		return err
	}

	switch args[0] {
	case "import":
		return importTunnels(args[1:])
	case "up":
		return up(args[1])
	case "install":
		path, err := existingConf(args[1])
		if err != nil {
			return err
		}
		return service.Install(path)
	case "uninstall":
		return service.Uninstall(args[1])
	case "start":
		return service.Start(args[1])
	case "stop":
		return service.Stop(args[1])
	case "status":
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		return status(name)
	case "manager":
		if args[1] == "install" {
			flags := args[2:]
			err := manager.Install(manager.Options{
				Boot: choice(flags, "--boot", "--no-boot"),
				User: flagValue(flags, "--user="),
			})
			if err != nil {
				return err
			}
			// The drivers install on demand and tunnels import later, so
			// failures here leave the install standing.
			ctx := context.Background()
			if hasFlag(flags, "--wireguard-driver") {
				if err := bootstrap.EnsureWireGuardNT(ctx); err != nil {
					log.Printf("Warning: %v; it installs when a VPN tunnel first connects", err)
				}
			}
			if hasFlag(flags, "--split-tunnel-driver") {
				if err := ensureSplitDriver(ctx); err != nil {
					log.Printf("Warning: split tunnel driver: %v; it installs when an include or exclude tunnel first connects", err)
				}
			}
			if hasFlag(flags, "--import") {
				if err := importTunnels(nil); err != nil {
					log.Printf("Warning: import: %v", err)
				}
			}
			return nil
		}
		if args[1] == "leave" {
			user := flagValue(args[2:], "--user=")
			if user == "" {
				var err error
				if user, err = manager.CurrentUser(); err != nil {
					return err
				}
			}
			return manager.Leave(user)
		}
		return manager.Uninstall()
	case "bootstrap":
		return bootstrapAll()
	case "update":
		return selfUpdate(args)
	case "cleanup":
		return cleanup(hasFlag(args[1:], "--configs"), !hasFlag(args[1:], "--keep-wireguardnt"))
	}
	return nil
}

func importTunnels(args []string) error {
	force := false
	var names []string
	for _, a := range args {
		switch {
		case a == "--force" || a == "-f":
			force = true
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown option %s", a)
		default:
			names = append(names, a)
		}
	}
	res, err := wgimport.Import(names, force)
	dir, _ := userconf.Dir()
	for _, n := range res.Imported {
		log.Printf("Imported %s to %s", n, filepath.Join(dir, n+".conf"))
	}
	for _, n := range res.Skipped {
		log.Printf("Skipped %s: %s already exists (--force overwrites it)", n, filepath.Join(dir, n+".conf"))
	}
	if err != nil {
		return err
	}
	if len(res.Imported) > 0 {
		log.Printf("Each imported file ends with a commented [SplitWire] section to edit")
	}
	return nil
}

func up(arg string) error {
	path, err := userconf.Resolve(arg)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) && !userconf.IsPath(arg) {
		log.Printf("%s does not exist; importing %s from the WireGuard app", path, arg)
		if _, err := wgimport.Import([]string{arg}, false); err != nil {
			return err
		}
	}
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Printf("Starting tunnel %s; press Ctrl+C to stop", c.WG.Name)
	return engine.Run(ctx, c)
}

// createWARP registers a Cloudflare WARP device and saves it as a tunnel
// named name, or name-2 and so on when that is taken.
func createWARP(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := warp.Register(ctx)
	if err != nil {
		return err
	}
	saved, err := userconf.CreateNew(name, d.Config())
	if err != nil {
		warp.Delete(ctx, d.ID, d.Token)
		return err
	}
	dir, _ := userconf.Dir()
	log.Printf("Created %s (Cloudflare WARP, %s account) in %s", saved, d.AccountType, dir)
	return nil
}

func runProxy(path string) error {
	if _, err := userconf.EnsureProxy(path); err != nil {
		return err
	}
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	p, err := proxy.Start(c)
	if err != nil {
		return err
	}
	log.Printf("Tunnel %s is up as a proxy: socks5://%s and http://%s; press Ctrl+C to stop", c.WG.Name, c.Proxy, c.Proxy)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()
	log.Printf("Shutting down proxy %s", c.WG.Name)
	p.Close()
	return nil
}

func check(path string) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	fmt.Printf("Tunnel      %s\n", c.WG.Name)
	fmt.Printf("Mode        %s\n", c.Mode)
	for _, p := range c.WG.Peers {
		ep := "(none)"
		if !p.Endpoint.IsEmpty() {
			ep = p.Endpoint.String()
		}
		fmt.Printf("Peer        %s at %s\n", p.PublicKey.String(), ep)
	}
	if len(c.WG.Interface.DNS) > 0 {
		fmt.Printf("DNS         %v for the whole system\n", c.WG.Interface.DNS)
	} else {
		fmt.Printf("DNS         system settings\n")
	}
	if c.WG.Interface.TableOff {
		fmt.Printf("Routes      none (Table = off)\n")
	} else {
		for _, f := range []struct {
			family winipcfg.AddressFamily
			label  string
		}{{windows.AF_INET, "IPv4"}, {windows.AF_INET6, "IPv6"}} {
			routes, warnings := netcfg.Routes(c, f.family)
			for _, r := range routes {
				fmt.Printf("Route       %-20s metric %d\n", r.Destination, r.Metric)
			}
			for _, w := range warnings {
				fmt.Printf("Warning     %s\n", w)
			}
		}
	}
	if c.Proxy.IsValid() {
		fmt.Printf("Proxy       %s when run as a proxy\n", c.Proxy)
	} else {
		fmt.Printf("Proxy       a free port from %d up, assigned when first run as a proxy\n", userconf.FirstProxyPort)
	}
	if c.Mode != config.ModeFull {
		paths, warnings, err := c.ExpandApps()
		if err != nil {
			return err
		}
		for _, w := range warnings {
			fmt.Printf("Warning     %s\n", w)
		}
		for _, p := range paths {
			note := ""
			if _, err := os.Stat(p); err != nil {
				note = " (not found yet)"
			}
			fmt.Printf("App         %s%s\n", p, note)
		}
		switch c.Mode {
		case config.ModeInclude:
			fmt.Println("\nListed apps and their child processes use only the tunnel; they cannot reach the local network.")
			if !c.HasDefaultRoute() {
				fmt.Println("AllowedIPs has no default route, so listed apps reach only the AllowedIPs ranges.")
			}
		case config.ModeExclude:
			fmt.Println("\nListed apps and their child processes bypass the tunnel.")
		}
	}
	return nil
}

// describe says how a manager tunnel runs.
func describe(t ipc.Tunnel) string {
	switch t.As {
	case ipc.AsProxy:
		return "proxy on " + t.Listen
	case ipc.AsSplit:
		return fmt.Sprintf("Split VPN, mode %s, %d apps", t.Mode, t.Apps)
	}
	return "VPN"
}

func apps(filter string) error {
	procs, err := stdriver.Processes()
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	var paths []string
	for _, p := range procs {
		if p.DOSPath == "" || seen[strings.ToLower(p.DOSPath)] {
			continue
		}
		if filter != "" && !strings.Contains(strings.ToLower(p.DOSPath), strings.ToLower(filter)) {
			continue
		}
		seen[strings.ToLower(p.DOSPath)] = true
		paths = append(paths, p.DOSPath)
	}
	sort.Slice(paths, func(i, j int) bool { return strings.ToLower(paths[i]) < strings.ToLower(paths[j]) })
	for _, p := range paths {
		fmt.Println(p)
	}
	if !elevate.IsElevated() {
		fmt.Fprintln(os.Stderr, "\nPrograms running as other users or elevated are hidden; run from an administrator console to list them.")
	}
	return nil
}

func status(name string) error {
	if dir, err := userconf.Dir(); err == nil {
		names, err := userconf.Names()
		if err != nil {
			return err
		}
		if len(names) == 0 {
			fmt.Printf("No tunnels in %s; `splitwire import` copies them from the WireGuard app.\n", dir)
		} else {
			fmt.Printf("Tunnels in %s: %s\n", dir, strings.Join(names, ", "))
		}
	}
	if manager.Installed() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		rep, err := ipc.Call(ctx, ipc.Request{Op: ipc.OpStatus})
		cancel()
		if err != nil {
			fmt.Printf("Manager: %v\n", err)
		} else {
			st := rep.Status
			boot := ""
			if st.Boot {
				boot = "; running tunnels come back when Windows starts"
			}
			fmt.Printf("Manager: %d tunnels%s\n", len(st.Tunnels), boot)
			for _, t := range st.Tunnels {
				fmt.Printf("  %s: %s, %s", t.Name, describe(t), t.State)
				if t.Error != "" {
					fmt.Printf(": %s", t.Error)
				}
				fmt.Println()
				for _, p := range t.Peers {
					fmt.Printf("    peer %s: handshake %s, received %s, sent %s\n", p.PublicKey, stats.Ago(p.LastHandshake), stats.Bytes(p.RxBytes), stats.Bytes(p.TxBytes))
				}
			}
			set := st.Settings
			on := map[bool]string{true: "on", false: "off"}
			fmt.Printf("Protection: kill switch %s, local network allowed %s, only the tunnels' DNS servers %s\n",
				on[set.KillSwitch], on[set.AllowLAN], on[set.StrictDNS])
			if len(set.Direct) > 0 {
				fmt.Printf("Always direct: %s\n", strings.Join(set.Direct, ", "))
			}
		}
	} else {
		fmt.Println("Manager: not installed (splitwire manager install)")
	}
	installed, err := service.List()
	if err != nil {
		return err
	}
	for _, in := range installed {
		fmt.Printf("Service %s: %s\n", service.Name(in.Tunnel), stateName(in.State))
		if in.State == svc.Running {
			if _, err := engine.PrintAdapterStatus(os.Stdout, in.Tunnel); err != nil {
				fmt.Printf("  %v\n", err)
			}
		}
	}
	if name != "" {
		found, err := engine.PrintAdapterStatus(os.Stdout, name)
		if err != nil {
			return err
		}
		if !found {
			fmt.Printf("No running tunnel named %s.\n", name)
		}
	}

	drv, err := stdriver.Open()
	switch {
	case errors.Is(err, stdriver.ErrNotLoaded):
		fmt.Println("Split tunnel driver: not loaded")
	case errors.Is(err, stdriver.ErrInUse):
		fmt.Println("Split tunnel driver: in use by a running tunnel")
	case err != nil:
		fmt.Printf("Split tunnel driver: %v\n", err)
	default:
		st, err := drv.State()
		drv.Close()
		if err != nil {
			return err
		}
		fmt.Printf("Split tunnel driver: loaded, %s\n", st)
	}
	return nil
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	}
	return fmt.Sprintf("state %d", s)
}

// selfUpdate installs the newest signed release over the installed copy,
// then runs the new executable's manager install, which restarts the
// manager service with it. The installed copy does the work, so the version
// it compares against is the installed one.
func selfUpdate(args []string) error {
	if !manager.Installed() {
		return errors.New("SplitWire is not installed; `splitwire manager install` installs this copy")
	}
	installed, err := bootstrap.ExePath()
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(self), filepath.Clean(installed)) {
		return runInstalled(installed, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	m, err := update.Latest(ctx)
	if err != nil {
		return err
	}
	if !update.Newer(m.Version, version) {
		log.Printf("SplitWire %s is the newest version", version)
		return nil
	}
	log.Printf("Downloading SplitWire %s", m.Version)
	exe, err := m.Download(ctx)
	if err != nil {
		return err
	}
	if err := bootstrap.ReplaceExe(exe); err != nil {
		return err
	}
	log.Printf("Installed SplitWire %s; restarting the manager service with it", m.Version)
	return runInstalled(installed, "manager", "install", "--wireguard-driver", "--split-tunnel-driver",
		"--user="+flagValue(args[1:], "--user="))
}

// runInstalled runs the installed executable with args in this console.
func runInstalled(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", exe, strings.Join(args, " "), err)
	}
	return nil
}

// direct lists the Always direct entries, or adds or removes some through
// the manager.
func direct(args []string) error {
	const usage = "usage: splitwire direct [add|remove <range, address or host name>...]"
	if !manager.Installed() {
		return errors.New("the SplitWire service is not installed (splitwire manager install)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rep, err := ipc.Call(ctx, ipc.Request{Op: ipc.OpStatus})
	if err != nil {
		return err
	}
	s := rep.Status.Settings
	if len(args) == 0 {
		if len(s.Direct) == 0 {
			fmt.Println("Always direct: nothing")
		}
		for _, e := range s.Direct {
			fmt.Println(e)
		}
		return nil
	}
	if len(args) < 2 {
		return errors.New(usage)
	}
	entries := args[1:]
	if _, err := config.ParseDirect(entries); err != nil {
		return err
	}
	switch args[0] {
	case "add":
		for _, e := range entries {
			if !slices.Contains(s.Direct, e) {
				s.Direct = append(s.Direct, e)
			}
		}
	case "remove":
		for _, e := range entries {
			i := slices.Index(s.Direct, e)
			if i < 0 {
				return fmt.Errorf("%s is not in the Always direct list", e)
			}
			s.Direct = slices.Delete(s.Direct, i, i+1)
		}
	default:
		return errors.New(usage)
	}
	if _, err := ipc.Call(ctx, ipc.Request{Op: ipc.OpSettings, Settings: &s}); err != nil {
		return err
	}
	fmt.Printf("Always direct: %s\n", strings.Join(s.Direct, ", "))
	return nil
}

// bootstrapAll installs wireguard.dll, the WireGuardNT driver and the
// split tunnel driver.
func bootstrapAll() error {
	ctx := context.Background()
	if err := bootstrap.EnsureDirs(); err != nil {
		return err
	}
	if err := bootstrap.EnsureWireGuardNT(ctx); err != nil {
		return err
	}
	if err := ensureSplitDriver(ctx); err != nil {
		return err
	}
	log.Printf("Ready: wireguard.dll, the WireGuardNT driver and the split tunnel driver (service %s running)", stdriver.ServiceName)
	return nil
}

// ensureSplitDriver installs the split tunnel driver and starts its service.
func ensureSplitDriver(ctx context.Context) error {
	if err := bootstrap.EnsureDirs(); err != nil {
		return err
	}
	sys, err := bootstrap.EnsureDriver(ctx)
	if err != nil {
		return err
	}
	return bootstrap.EnsureDriverService(sys)
}

// cleanup removes everything splitwire installed: its services, the split
// tunnel driver, firewall objects, Program Files\splitwire, the sign-in
// entry and temporary files. With wireguardNT, the WireGuardNT driver goes
// too unless the WireGuard app, which shares it, is installed. With
// configs, the tunnel configurations in %APPDATA%\splitwire go as well.
func cleanup(configs, wireguardNT bool) error {
	installed, err := service.List()
	if err != nil {
		return err
	}
	for _, in := range installed {
		if err := service.Uninstall(in.Tunnel); err != nil {
			return err
		}
	}
	if err := manager.Uninstall(); err != nil {
		return err
	}
	if err := wgimport.RemoveHelperService(); err != nil {
		log.Printf("Warning: %v", err)
	}
	drv, err := stdriver.Open()
	switch {
	case errors.Is(err, stdriver.ErrInUse):
		return errors.New("a tunnel is using the split tunnel driver; stop it first")
	case err == nil:
		if err := drv.Reset(); err != nil {
			log.Printf("Warning: %v", err)
		}
		drv.Close()
	}
	if err := bootstrap.RemoveDriverService(); err != nil {
		return err
	}
	if err := firewall.RemoveSublayers(); err != nil {
		log.Printf("Warning: remove firewall sublayers: %v", err)
	}
	if wireguardNT {
		removeWireGuardNT()
	}

	root, err := bootstrap.Root()
	if err != nil {
		return err
	}
	pending, err := bootstrap.RemoveRoot()
	if err != nil {
		return err
	}
	if pending > 0 {
		log.Printf("Removed %s except %d files and folders in use, which go at the next restart", root, pending)
	} else {
		log.Printf("Removed %s", root)
	}

	for _, where := range []func(string) (string, error){shortcut.StartMenu, shortcut.CommonStartMenu} {
		if lnk, err := where(tray.StartMenuName); err == nil && os.Remove(lnk) == nil {
			log.Printf("Removed the Start menu shortcut %s", lnk)
		}
	}
	if err := tray.RemoveRunAtLogin(); err != nil {
		log.Printf("Warning: remove the sign-in entry: %v", err)
	}
	tray.RemoveTempFiles()
	if configs {
		dir, err := userconf.Dir()
		if err != nil {
			return err
		}
		if err := os.RemoveAll(dir); err != nil {
			return fmt.Errorf("remove %s: %w", dir, err)
		}
		log.Printf("Removed %s", dir)
	} else if dir, err := userconf.Dir(); err == nil {
		log.Printf("Kept the tunnel configurations in %s", dir)
	}
	return nil
}

// removeWireGuardNT deletes the WireGuardNT driver when the WireGuard app
// is not installed. The driver refuses while any WireGuard adapter exists.
func removeWireGuardNT() {
	if wgimport.AppInstalled() {
		log.Printf("The WireGuardNT driver stays installed; the WireGuard app uses it")
		return
	}
	dll, err := bootstrap.DLLPath()
	if err != nil {
		return
	}
	if _, err := os.Stat(dll); err != nil {
		return
	}
	if err := bootstrap.LoadWireGuardDLL(dll); err != nil {
		log.Printf("Warning: %v", err)
		return
	}
	if err := driver.Uninstall(); err != nil {
		log.Printf("Warning: remove the WireGuardNT driver: %v", err)
		return
	}
	log.Printf("Removed the WireGuardNT driver")
}

// Command splitwire runs WireGuard tunnels on Windows with per-app split tunneling.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"splitwire/internal/bootstrap"
	"splitwire/internal/config"
	"splitwire/internal/elevate"
	"splitwire/internal/engine"
	"splitwire/internal/firewall"
	"splitwire/internal/logx"
	"splitwire/internal/netcfg"
	"splitwire/internal/service"
	"splitwire/internal/stdriver"
)

const version = "0.1.0"

const usage = `splitwire ` + version + ` - WireGuard with per-app split tunneling

Usage:
  splitwire up <tunnel.conf>        Run a tunnel in this console until Ctrl+C
  splitwire check <tunnel.conf>     Validate a configuration and show its effect
  splitwire apps [filter]           List running programs with their paths
  splitwire install <tunnel.conf>   Install a tunnel as a service that starts at boot
  splitwire uninstall <name>        Stop and remove an installed tunnel
  splitwire start <name>            Start an installed tunnel
  splitwire stop <name>             Stop an installed tunnel
  splitwire status [name]           Show installed tunnels, the driver and peer statistics
  splitwire bootstrap               Install wireguard.dll and the split tunnel driver
  splitwire cleanup                 Remove the driver service, firewall objects and files
  splitwire version

Commands that change the system ask for administrator rights.
`

func main() {
	args := os.Args[1:]
	hold := false
	if len(args) > 0 && args[0] == elevate.HoldFlag {
		hold = true
		args = args[1:]
	}
	err := run(args)
	if err != nil {
		log.Printf("Error: %v", err)
	}
	if hold {
		elevate.WaitForEnter()
	}
	if err != nil {
		os.Exit(1)
	}
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

func absArg(args []string) []string {
	out := append([]string(nil), args...)
	if len(out) == 2 {
		if p, err := filepath.Abs(out[1]); err == nil {
			out[1] = p
		}
	}
	return out
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
		path, err := needArg(args, "<tunnel.conf>")
		if err != nil {
			return err
		}
		return check(path)
	case "apps":
		filter := ""
		if len(args) > 1 {
			filter = strings.Join(args[1:], " ")
		}
		return apps(filter)
	}

	switch args[0] {
	case "up", "install":
		if _, err := needArg(args, "<tunnel.conf>"); err != nil {
			return err
		}
		args = absArg(args)
	case "uninstall", "start", "stop":
		if _, err := needArg(args, "<name>"); err != nil {
			return err
		}
	case "status", "bootstrap", "cleanup":
	default:
		return fmt.Errorf("unknown command %q; run splitwire help", args[0])
	}
	if relaunched, err := requireAdmin(args); relaunched || err != nil {
		return err
	}

	switch args[0] {
	case "up":
		return up(args[1])
	case "install":
		return service.Install(args[1])
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
	case "bootstrap":
		return bootstrapAll()
	case "cleanup":
		return cleanup()
	}
	return nil
}

func up(path string) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	log.Printf("Starting tunnel %s; press Ctrl+C to stop", c.WG.Name)
	return engine.Run(ctx, c)
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
	if c.Mode == config.ModeInclude {
		fmt.Printf("Kill switch listed apps only (always on in include mode)\n")
	} else {
		fmt.Printf("Kill switch %s\n", onOff(c.KillSwitchOn()))
	}
	if c.KillSwitchOn() {
		fmt.Printf("LAN         %s\n", map[bool]string{true: "allowed", false: "blocked"}[c.AllowLAN])
	}
	if len(c.WG.Interface.DNS) > 0 {
		strict := ""
		if c.StrictDNS {
			strict = ", other DNS servers blocked"
		}
		fmt.Printf("DNS         %v for the whole system%s\n", c.WG.Interface.DNS, strict)
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

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
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
	installed, err := service.List()
	if err != nil {
		return err
	}
	if len(installed) == 0 {
		fmt.Println("No tunnels installed as services.")
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

func bootstrapAll() error {
	ctx := context.Background()
	if err := bootstrap.EnsureDirs(); err != nil {
		return err
	}
	dll, err := bootstrap.EnsureWireGuardDLL(ctx)
	if err != nil {
		return err
	}
	sys, err := bootstrap.EnsureDriver(ctx)
	if err != nil {
		return err
	}
	if err := bootstrap.EnsureDriverService(sys); err != nil {
		return err
	}
	log.Printf("Ready: %s, %s (driver service %s running)", dll, sys, stdriver.ServiceName)
	return nil
}

func cleanup() error {
	installed, err := service.List()
	if err != nil {
		return err
	}
	if len(installed) > 0 {
		names := make([]string, len(installed))
		for i, in := range installed {
			names[i] = in.Tunnel
		}
		return fmt.Errorf("uninstall these tunnels first: %s", strings.Join(names, ", "))
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
	root, err := bootstrap.Root()
	if err != nil {
		return err
	}
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("remove %s: %w", root, err)
	}
	log.Printf("Removed %s", root)
	log.Printf("The WireGuardNT driver stays installed; the WireGuard app shares it")
	return nil
}

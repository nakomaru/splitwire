/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Adapted for splitwire from tunnel/mtumonitor.go of wireguard-windows.
 */

package netcfg

import (
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// MonitorMTU keeps the tunnel MTU at the physical default interface's MTU
// minus WireGuard's 80 bytes of overhead. It is used when [Interface] sets
// no MTU.
func MonitorMTU(family winipcfg.AddressFamily, ourLUID winipcfg.LUID) ([]winipcfg.ChangeCallback, error) {
	minMTU := 576
	if family == windows.AF_INET6 {
		minMTU = 1280
	}
	var mu sync.Mutex
	lastMTU := uint32(0)
	doIt := func() error {
		mu.Lock()
		defer mu.Unlock()
		luid, err := defaultInterface(family, ourLUID)
		if err != nil {
			return err
		}
		mtu := uint32(0)
		if luid != 0 {
			iface, err := luid.Interface()
			if err != nil {
				return err
			}
			mtu = iface.MTU
		}
		if mtu > 0 && lastMTU != mtu {
			iface, err := ourLUID.IPInterface(family)
			if err != nil {
				return err
			}
			iface.NLMTU = uint32(max(int(mtu)-80, minMTU))
			if err := iface.Set(); err != nil {
				return err
			}
			lastMTU = mtu
		}
		return nil
	}
	if err := doIt(); err != nil {
		return nil, err
	}
	cbr, err := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			doIt()
		}
	})
	if err != nil {
		return nil, err
	}
	cbi, err := winipcfg.RegisterInterfaceChangeCallback(func(nt winipcfg.MibNotificationType, _ *winipcfg.MibIPInterfaceRow) {
		if nt == winipcfg.MibParameterNotification {
			doIt()
		}
	})
	if err != nil {
		cbr.Unregister()
		return nil, err
	}
	return []winipcfg.ChangeCallback{cbr, cbi}, nil
}

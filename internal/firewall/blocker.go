/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 * Modified for splitwire: fixed provider and sublayer keys shared with the
 * split tunnel driver, a separate DNS sublayer, endpoint and LAN permits.
 */

package firewall

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
	dns      windows.GUID
}

// Keys of the provider and sublayers. The split tunnel driver receives the
// sublayer keys at initialization and registers its own permit filters in
// them, at weights above every filter installed here.
var (
	ProviderKey = windows.GUID{Data1: 0x70768e22, Data2: 0x8e73, Data3: 0x4836, Data4: [8]byte{0xb6, 0xc1, 0xcd, 0xab, 0xd4, 0xff, 0x7e, 0xf9}}
	BaselineKey = windows.GUID{Data1: 0x5fc292a3, Data2: 0xcf3c, Data3: 0x4d37, Data4: [8]byte{0xb0, 0x83, 0xbd, 0xec, 0x1b, 0xb7, 0x5d, 0x42}}
	DNSKey      = windows.GUID{Data1: 0x96095432, Data2: 0xb1ed, Data3: 0x4f72, Data4: [8]byte{0x8f, 0xd8, 0xff, 0x64, 0xf2, 0x36, 0x39, 0x4f}}
)

const (
	errFwpProviderNotFound = windows.Errno(0x80320005)
	errFwpSublayerNotFound = windows.Errno(0x80320007)
	errFwpAlreadyExists    = windows.Errno(0x80320009)

	cFWPM_SESSION_FLAG_NONE wtFwpmSessionFlagsValue = 0

	sublayerWeightBaseline = ^uint16(0)
	sublayerWeightDNS      = ^uint16(0) - 1
)

// Options selects the blocking filters Block installs. Each tunnel's
// Permits let its own traffic through them.
type Options struct {
	// KillSwitch blocks all traffic except loopback, DHCP, NDP, what Permits
	// allow and, with AllowLAN, private networks.
	KillSwitch bool
	AllowLAN   bool
	// BlockDNS blocks DNS to every server Permits do not allow.
	BlockDNS bool
}

func openSession(flags wtFwpmSessionFlagsValue, description string) (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("splitwire", description)
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                flags,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

// EnsureSublayers registers the provider and both sublayers. They outlive the
// calling process, so the driver's filters stay valid if splitwire exits
// unexpectedly; they disappear at reboot or through RemoveSublayers.
func EnsureSublayers() error {
	session, err := openSession(cFWPM_SESSION_FLAG_NONE, "splitwire static session")
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)

	return runTransaction(session, func(session uintptr) error {
		displayData, err := createWtFwpmDisplayData0("splitwire", "splitwire provider")
		if err != nil {
			return wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: ProviderKey,
			displayData: *displayData,
		}
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil && !errors.Is(err, errFwpAlreadyExists) {
			return wrapErr(err)
		}

		for _, s := range []struct {
			key         windows.GUID
			name, descr string
			weight      uint16
		}{
			{BaselineKey, "splitwire filters", "Permissive and blocking filters", sublayerWeightBaseline},
			{DNSKey, "splitwire DNS filters", "DNS restriction filters", sublayerWeightDNS},
		} {
			displayData, err := createWtFwpmDisplayData0(s.name, s.descr)
			if err != nil {
				return wrapErr(err)
			}
			providerKey := ProviderKey
			sublayer := wtFwpmSublayer0{
				subLayerKey: s.key,
				displayData: *displayData,
				providerKey: &providerKey,
				weight:      s.weight,
			}
			err = fwpmSubLayerAdd0(session, &sublayer, 0)
			if err != nil && !errors.Is(err, errFwpAlreadyExists) {
				return wrapErr(err)
			}
		}
		return nil
	})
}

// RemoveSublayers deletes the sublayers and provider. It fails while any
// filter, including the driver's, still references them.
func RemoveSublayers() error {
	session, err := openSession(cFWPM_SESSION_FLAG_NONE, "splitwire static session")
	if err != nil {
		return err
	}
	defer fwpmEngineClose0(session)

	for _, key := range []windows.GUID{BaselineKey, DNSKey} {
		err = fwpmSubLayerDeleteByKey0(session, &key)
		if err != nil && !errors.Is(err, errFwpSublayerNotFound) {
			return wrapErr(err)
		}
	}
	err = fwpmProviderDeleteByKey0(session, &ProviderKey)
	if err != nil && !errors.Is(err, errFwpProviderNotFound) {
		return wrapErr(err)
	}
	return nil
}

// Blocker holds installed blocking filters. They live in a dynamic
// session, so Close or the process exiting removes them.
type Blocker struct {
	session uintptr
}

// Block installs the filters opts selects, or nothing when it selects
// none. EnsureSublayers must run first.
func Block(opts Options) (*Blocker, error) {
	if !opts.KillSwitch && !opts.BlockDNS {
		return nil, nil
	}
	session, err := openSession(cFWPM_SESSION_FLAG_DYNAMIC, "splitwire blocking filters")
	if err != nil {
		return nil, wrapErr(err)
	}
	baseObjects := &baseObjects{provider: ProviderKey, filters: BaselineKey, dns: DNSKey}
	err = runTransaction(session, func(session uintptr) error {
		if opts.BlockDNS {
			if err := blockDNS(nil, session, baseObjects, 15, 14); err != nil {
				return wrapErr(err)
			}
		}
		if !opts.KillSwitch {
			return nil
		}
		for _, permit := range []func() error{
			func() error { return permitLoopback(session, baseObjects, 13) },
			func() error { return permitDHCPIPv4(session, baseObjects, 12) },
			func() error { return permitDHCPIPv6(session, baseObjects, 12) },
			func() error { return permitNdp(session, baseObjects, 12) },
		} {
			if err := permit(); err != nil {
				return wrapErr(err)
			}
		}
		if opts.AllowLAN {
			if err := permitLAN(session, baseObjects, 12); err != nil {
				return wrapErr(err)
			}
		}
		return wrapErr(blockAll(session, baseObjects, 0))
	})
	if err != nil {
		fwpmEngineClose0(session)
		return nil, wrapErr(err)
	}
	return &Blocker{session: session}, nil
}

// Close removes the filters.
func (b *Blocker) Close() {
	if b != nil && b.session != 0 {
		fwpmEngineClose0(b.session)
		b.session = 0
	}
}

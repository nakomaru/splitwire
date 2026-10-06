package firewall

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procFwpmSubLayerDeleteByKey0 = modfwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procFwpmProviderDeleteByKey0 = modfwpuclnt.NewProc("FwpmProviderDeleteByKey0")
)

func fwpmSubLayerDeleteByKey0(engineHandle uintptr, key *windows.GUID) error {
	r1, _, _ := procFwpmSubLayerDeleteByKey0.Call(engineHandle, uintptr(unsafe.Pointer(key)))
	if r1 != 0 {
		return windows.Errno(r1)
	}
	return nil
}

func fwpmProviderDeleteByKey0(engineHandle uintptr, key *windows.GUID) error {
	r1, _, _ := procFwpmProviderDeleteByKey0.Call(engineHandle, uintptr(unsafe.Pointer(key)))
	if r1 != 0 {
		return windows.Errno(r1)
	}
	return nil
}

// Private, link-local and multicast ranges permitted by permitLAN.
var (
	lanPrefixes4 = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
	}
	lanPrefixes6 = []netip.Prefix{
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("ff00::/8"),
	}
)

// addBothDirections adds filter at the outbound and inbound ALE auth layers of
// one address family.
func addBothDirections(session uintptr, filter *wtFwpmFilter0, ipv6 bool, name string) error {
	family, connect, recv := "IPv4", cFWPM_LAYER_ALE_AUTH_CONNECT_V4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
	if ipv6 {
		family, connect, recv = "IPv6", cFWPM_LAYER_ALE_AUTH_CONNECT_V6, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
	}
	for _, l := range []struct {
		layer     windows.GUID
		direction string
	}{{connect, "outbound"}, {recv, "inbound"}} {
		displayData, err := createWtFwpmDisplayData0(fmt.Sprintf("%s %s (%s)", name, l.direction, family), "")
		if err != nil {
			return wrapErr(err)
		}
		filter.displayData = *displayData
		filter.layerKey = l.layer
		filterID := uint64(0)
		err = fwpmFilterAdd0(session, filter, 0, &filterID)
		if err != nil {
			return wrapErr(err)
		}
	}
	return nil
}

// permitEndpoints permits UDP to and from each peer endpoint, so the tunnel
// itself survives the kill switch.
func permitEndpoints(session uintptr, baseObjects *baseObjects, weight uint8, endpoints []netip.AddrPort) error {
	for _, ep := range endpoints {
		conditions := []wtFwpmFilterCondition0{
			{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT16,
					value: uintptr(ep.Port()),
				},
			},
			{
				fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT8,
					value: uintptr(cIPPROTO_UDP),
				},
			},
		}
		addr := ep.Addr().Unmap()
		var address *wtFwpByteArray16
		if addr.Is4() {
			conditions = append(conditions, wtFwpmFilterCondition0{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT32,
					value: uintptr(binary.BigEndian.Uint32(addr.AsSlice())),
				},
			})
		} else {
			address = &wtFwpByteArray16{byteArray16: addr.As16()}
			conditions = append(conditions, wtFwpmFilterCondition0{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_BYTE_ARRAY16_TYPE,
					value: uintptr(unsafe.Pointer(address)),
				},
			})
		}

		filter := wtFwpmFilter0{
			providerKey:         &baseObjects.provider,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}
		err := addBothDirections(session, &filter, !addr.Is4(), "Permit WireGuard endpoint "+ep.String())
		runtime.KeepAlive(address)
		if err != nil {
			return err
		}
	}
	return nil
}

// permitLAN permits traffic with private, link-local and multicast peers.
func permitLAN(session uintptr, baseObjects *baseObjects, weight uint8) error {
	// Repeated conditions on one field combine with logical OR.
	masks4 := make([]wtFwpV4AddrAndMask, len(lanPrefixes4))
	conditions4 := make([]wtFwpmFilterCondition0, len(lanPrefixes4))
	for i, p := range lanPrefixes4 {
		masks4[i] = wtFwpV4AddrAndMask{
			addr: binary.BigEndian.Uint32(p.Addr().AsSlice()),
			mask: ^uint32(0) << (32 - p.Bits()),
		}
		conditions4[i] = wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V4_ADDR_MASK,
				value: uintptr(unsafe.Pointer(&masks4[i])),
			},
		}
	}
	masks6 := make([]wtFwpV6AddrAndMask, len(lanPrefixes6))
	conditions6 := make([]wtFwpmFilterCondition0, len(lanPrefixes6))
	for i, p := range lanPrefixes6 {
		masks6[i] = wtFwpV6AddrAndMask{addr: p.Addr().As16(), prefixLength: uint8(p.Bits())}
		conditions6[i] = wtFwpmFilterCondition0{
			fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
			matchType: cFWP_MATCH_EQUAL,
			conditionValue: wtFwpConditionValue0{
				_type: cFWP_V6_ADDR_MASK,
				value: uintptr(unsafe.Pointer(&masks6[i])),
			},
		}
	}

	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: uint32(len(conditions4)),
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions4[0])),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}
	err := addBothDirections(session, &filter, false, "Permit LAN")
	if err != nil {
		return err
	}
	filter.numFilterConditions = uint32(len(conditions6))
	filter.filterCondition = (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions6[0]))
	err = addBothDirections(session, &filter, true, "Permit LAN")
	runtime.KeepAlive(masks4)
	runtime.KeepAlive(masks6)
	return err
}

// permitDNS permits DNS to and from servers, past blockDNS's deny filters.
func permitDNS(session uintptr, baseObjects *baseObjects, weight uint8, servers []netip.Addr) error {
	for _, ipv6 := range []bool{false, true} {
		// Repeated conditions on one field combine with logical OR.
		conditions := []wtFwpmFilterCondition0{
			{
				fieldKey:  cFWPM_CONDITION_IP_REMOTE_PORT,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT16,
					value: uintptr(53),
				},
			},
			{
				fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT8,
					value: uintptr(cIPPROTO_UDP),
				},
			},
			{
				fieldKey:  cFWPM_CONDITION_IP_PROTOCOL,
				matchType: cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{
					_type: cFWP_UINT8,
					value: uintptr(cIPPROTO_TCP),
				},
			},
		}
		base := len(conditions)
		var addresses []*wtFwpByteArray16
		for _, ip := range servers {
			ip = ip.Unmap()
			if ip.Is6() != ipv6 {
				continue
			}
			c := wtFwpmFilterCondition0{fieldKey: cFWPM_CONDITION_IP_REMOTE_ADDRESS, matchType: cFWP_MATCH_EQUAL}
			if ipv6 {
				a := &wtFwpByteArray16{byteArray16: ip.As16()}
				addresses = append(addresses, a)
				c.conditionValue = wtFwpConditionValue0{_type: cFWP_BYTE_ARRAY16_TYPE, value: uintptr(unsafe.Pointer(a))}
			} else {
				c.conditionValue = wtFwpConditionValue0{_type: cFWP_UINT32, value: uintptr(binary.BigEndian.Uint32(ip.AsSlice()))}
			}
			conditions = append(conditions, c)
		}
		if len(conditions) == base {
			continue
		}
		filter := wtFwpmFilter0{
			providerKey:         &baseObjects.provider,
			subLayerKey:         baseObjects.dns,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}
		err := addBothDirections(session, &filter, ipv6, "Permit tunnel DNS")
		runtime.KeepAlive(addresses)
		if err != nil {
			return err
		}
	}
	return nil
}

// Permits let one tunnel through the kill switch and DNS restriction of
// another: its adapter, its peer endpoints and its DNS servers. They live in
// their own dynamic session, so Close or the process exiting removes them.
type Permits struct {
	session uintptr
}

// Permit installs the permits of the tunnel on tunnelLUID. EnsureSublayers
// must run first.
func Permit(tunnelLUID uint64, endpoints []netip.AddrPort, dns []netip.Addr) (*Permits, error) {
	session, err := openSession(cFWPM_SESSION_FLAG_DYNAMIC, "splitwire tunnel permits")
	if err != nil {
		return nil, err
	}
	base := &baseObjects{provider: ProviderKey, filters: BaselineKey, dns: DNSKey}
	err = runTransaction(session, func(session uintptr) error {
		if err := permitTunInterface(session, base, 12, tunnelLUID); err != nil {
			return err
		}
		if err := permitEndpoints(session, base, 12, endpoints); err != nil {
			return err
		}
		return permitDNS(session, base, 15, dns)
	})
	if err != nil {
		fwpmEngineClose0(session)
		return nil, wrapErr(err)
	}
	return &Permits{session: session}, nil
}

// Close removes the permits.
func (p *Permits) Close() {
	if p != nil && p.session != 0 {
		fwpmEngineClose0(p.session)
		p.session = 0
	}
}

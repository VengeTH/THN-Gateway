package network

import "encoding/json"

// ipLinkJSON mirrors the subset of `ip -j -d link show` output that THN uses.
//
// Decoding into a struct rather than a map gives a clear error instead of a nil
// interface somewhere downstream. The cost is that a field with the wrong Go
// type is not tolerated by the decoder, and `ip` is not a stable interface — so
// every field here is one THN actually reads, and adding one "just in case" is
// how a gateway ends up unable to see itself.
//
// Four such fields were present and have been removed. One of them,
// `link_netnsid`, was declared as a string; `ip` emits it as a number on any
// interface in a network namespace, so the decoder failed on the whole
// document and THN reported a gateway with no interfaces at all. It was never
// read. That is the failure this comment exists to prevent.
type ipLinkJSON struct {
	IfName    string         `json:"ifname"`
	IfIndex   int            `json:"ifindex"`
	MTU       int            `json:"mtu"`
	Operstate string         `json:"operstate"`
	Address   string         `json:"address"`
	Flags     []string       `json:"flags"`
	LinkInfo  ipLinkInfoJSON `json:"linkinfo"`
	// Speed is the negotiated link speed in Mbps.
	//
	// `ip` emits it only when a driver reports one. A field that THN
	// declared with the wrong Go type would fail the whole document, so it
	// is declared as the plain number the kernel emits. Absent means the
	// driver does not report a speed — which is NOT the same as a speed of
	// zero, and is carried through as 0 meaning "not reported".
	Speed int `json:"speed"`

	// LinkType is the kernel's `link_type`: "ether", "loopback", "ppp".
	//
	// Together with linkinfo.info_kind it is what lets THN tell a real NIC
	// from a virtual one WITHOUT looking at the interface name. `ip` reports
	// "ether" for onboard, USB and virtual-ethernet alike; the absence of any
	// virtual info_kind is what distinguishes the physical case.
	LinkType string `json:"link_type"`

	// Master names the bond or bridge this interface is enslaved to, empty
	// otherwise.
	//
	// A NIC inside a bond is still physical hardware. Recording this keeps
	// the distinction available without having to classify it a second way.
	Master string `json:"master"`

	// Wireless is present ONLY on wireless interfaces, and the kernel emits
	// it because `ip` was given `-d`.
	//
	// It is declared as RawMessage rather than a typed struct on purpose. A
	// shape change inside this object — a new key, a field changing type —
	// cannot then fail the decode of the whole document and make THN report
	// a gateway with no interfaces. wirelessMode re-decodes it separately,
	// and that decode failing costs one field rather than the host.
	Wireless json.RawMessage `json:"wireless"`
}

// ipWirelessJSON is the subset of the `wireless` object THN reads.
//
// iftype is what decides wireless-client versus wireless-ap: a NIC in
// "managed" mode is a client, in "ap" mode it is an access point. That
// distinction is the difference between a capability being available and
// merely present, so it is worth decoding even though it is one field.
//
// SSID is deliberately NOT collected. The network name identifies where a
// person is, it changes without the hardware changing, and no routing or
// firewall decision THN makes depends on it.
type ipWirelessJSON struct {
	Iftype string `json:"iftype"`
	Mode   string `json:"mode"`
}

type ipLinkInfoJSON struct {
	InfoKind string `json:"info_kind"`
	InfoData any    `json:"info_data"`
}

// ipAddrJSON mirrors `ip -j addr show`.
type ipAddrJSON struct {
	IfName   string           `json:"ifname"`
	IfIndex  int              `json:"ifindex"`
	AddrInfo []ipAddrInfoJSON `json:"addr_info"`
}

type ipAddrInfoJSON struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
	Scope     string `json:"scope"`
	Label     string `json:"label,omitempty"`
}

// ipRouteJSON mirrors `ip -j route show`.
//
// `type` is deliberately absent. `ip` reports it as a string on most versions
// and it has been observed as an object on others, so declaring it either way
// risks the same whole-document decode failure described on ipLinkJSON.
type ipRouteJSON struct {
	Destination string   `json:"dst"`
	Gateway     string   `json:"gateway"`
	Dev         string   `json:"dev"`
	Protocol    string   `json:"protocol"`
	Scope       string   `json:"scope"`
	Metric      int      `json:"metric"`
	Flags       []string `json:"flags"`
}

// ipNeighJSON mirrors `ip -j neigh show`.
type ipNeighJSON struct {
	Dst    string   `json:"dst"`
	Dev    string   `json:"dev"`
	Lladdr string   `json:"lladdr"`
	State  []string `json:"state"`
	Router bool     `json:"router"`
	Failed bool     `json:"failed"`
}

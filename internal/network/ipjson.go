package network

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

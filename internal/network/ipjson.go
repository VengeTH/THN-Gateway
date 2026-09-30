package network

// ipLinkJSON mirrors the subset of `ip -j -d link show` output that THN uses.
//
// Only the fields THN actually reads are declared. Decoding into a struct
// rather than a map means an unexpected value type produces a clear error
// instead of a nil interface somewhere downstream.
type ipLinkJSON struct {
	IfName    string          `json:"ifname"`
	IfIndex   int             `json:"ifindex"`
	MTU       int             `json:"mtu"`
	Operstate string          `json:"operstate"`
	Address   string          `json:"address"`
	Flags     []string        `json:"flags"`
	LinkType  string          `json:"link_type"`
	LinkInfo  ipLinkInfoJSON  `json:"linkinfo"`
	LinkNetNS string          `json:"link_netnsid"`
	Extra     map[string]bool `json:"-"`
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
type ipRouteJSON struct {
	Destination string   `json:"dst"`
	Gateway     string   `json:"gateway"`
	Dev         string   `json:"dev"`
	Protocol    string   `json:"protocol"`
	Scope       string   `json:"scope"`
	Metric      int      `json:"metric"`
	Type        string   `json:"type"`
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

package execution

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/venth/thn-gateway/internal/diff"
	"github.com/venth/thn-gateway/internal/planner"
)

var ifaceRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{1,16}$`)

// OpKind names a structured networking operation.
type OpKind string

const (
	OpKindLinkSetUp         OpKind = "link_set_up"
	OpKindLinkSetDown       OpKind = "link_set_down"
	OpKindAddressAdd        OpKind = "address_add"
	OpKindAddressDelete     OpKind = "address_delete"
	OpKindRouteAdd          OpKind = "route_add"
	OpKindRouteReplace      OpKind = "route_replace"
	OpKindRouteDelete       OpKind = "route_delete"
	OpKindSysctlSet         OpKind = "sysctl_set"
	OpKindNFTApplyTHNTable  OpKind = "nft_apply_thn_table"
	OpKindNFTDeleteTHNTable OpKind = "nft_delete_thn_table"
	OpKindQDiscApply        OpKind = "qdisc_apply"
	OpKindQDiscDelete       OpKind = "qdisc_delete"
	OpKindDNSApply          OpKind = "dns_apply"
)

// Operation represents a structured network mutation with bounded parameters.
type Operation interface {
	Kind() OpKind
	Target() string
	Subsystem() string
	Validate() error
	RollbackOp() Operation
	RequiredCapabilities() []string
	RenderCommand() string
}

// ---------------------------------------------------------------- link ops

type OpLinkSetUp struct {
	Interface string `json:"interface"`
}

func (o OpLinkSetUp) Kind() OpKind                   { return OpKindLinkSetUp }
func (o OpLinkSetUp) Target() string                 { return o.Interface }
func (o OpLinkSetUp) Subsystem() string              { return "link" }
func (o OpLinkSetUp) RequiredCapabilities() []string { return []string{"ip"} }
func (o OpLinkSetUp) RollbackOp() Operation          { return OpLinkSetDown{Interface: o.Interface} }
func (o OpLinkSetUp) RenderCommand() string          { return fmt.Sprintf("ip link set %s up", o.Interface) }
func (o OpLinkSetUp) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface name: %q", o.Interface)
	}
	return nil
}

type OpLinkSetDown struct {
	Interface string `json:"interface"`
}

func (o OpLinkSetDown) Kind() OpKind                   { return OpKindLinkSetDown }
func (o OpLinkSetDown) Target() string                 { return o.Interface }
func (o OpLinkSetDown) Subsystem() string              { return "link" }
func (o OpLinkSetDown) RequiredCapabilities() []string { return []string{"ip"} }
func (o OpLinkSetDown) RollbackOp() Operation          { return OpLinkSetUp{Interface: o.Interface} }
func (o OpLinkSetDown) RenderCommand() string          { return fmt.Sprintf("ip link set %s down", o.Interface) }
func (o OpLinkSetDown) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface name: %q", o.Interface)
	}
	return nil
}

// ------------------------------------------------------------- address ops

type OpAddressAdd struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
}

func (o OpAddressAdd) Kind() OpKind                   { return OpKindAddressAdd }
func (o OpAddressAdd) Target() string                 { return fmt.Sprintf("%s dev %s", o.CIDR, o.Interface) }
func (o OpAddressAdd) Subsystem() string              { return "address" }
func (o OpAddressAdd) RequiredCapabilities() []string { return []string{"ip"} }
func (o OpAddressAdd) RollbackOp() Operation {
	return OpAddressDelete{Interface: o.Interface, CIDR: o.CIDR}
}
func (o OpAddressAdd) RenderCommand() string {
	return fmt.Sprintf("ip addr add %s dev %s", o.CIDR, o.Interface)
}
func (o OpAddressAdd) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface name: %q", o.Interface)
	}
	if _, err := netip.ParsePrefix(o.CIDR); err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", o.CIDR, err)
	}
	return nil
}

type OpAddressDelete struct {
	Interface string `json:"interface"`
	CIDR      string `json:"cidr"`
}

func (o OpAddressDelete) Kind() OpKind                   { return OpKindAddressDelete }
func (o OpAddressDelete) Target() string                 { return fmt.Sprintf("%s dev %s", o.CIDR, o.Interface) }
func (o OpAddressDelete) Subsystem() string              { return "address" }
func (o OpAddressDelete) RequiredCapabilities() []string { return []string{"ip"} }
func (o OpAddressDelete) RollbackOp() Operation {
	return OpAddressAdd{Interface: o.Interface, CIDR: o.CIDR}
}
func (o OpAddressDelete) RenderCommand() string {
	return fmt.Sprintf("ip addr del %s dev %s", o.CIDR, o.Interface)
}
func (o OpAddressDelete) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface name: %q", o.Interface)
	}
	if _, err := netip.ParsePrefix(o.CIDR); err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", o.CIDR, err)
	}
	return nil
}

// --------------------------------------------------------------- route ops

type OpRouteAdd struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Device      string `json:"device,omitempty"`
}

func (o OpRouteAdd) Kind() OpKind                   { return OpKindRouteAdd }
func (o OpRouteAdd) Target() string                 { return o.Destination }
func (o OpRouteAdd) Subsystem() string              { return "route" }
func (o OpRouteAdd) RequiredCapabilities() []string { return []string{"ip"} }
func (o OpRouteAdd) RollbackOp() Operation {
	return OpRouteDelete{Destination: o.Destination, Gateway: o.Gateway, Device: o.Device}
}
func (o OpRouteAdd) RenderCommand() string {
	cmd := fmt.Sprintf("ip route add %s via %s", o.Destination, o.Gateway)
	if o.Device != "" {
		cmd += " dev " + o.Device
	}
	return cmd
}
func (o OpRouteAdd) Validate() error {
	if o.Destination != "default" {
		if _, err := netip.ParsePrefix(o.Destination); err != nil {
			return fmt.Errorf("invalid route destination %q: %w", o.Destination, err)
		}
	}
	if _, err := netip.ParseAddr(o.Gateway); err != nil {
		return fmt.Errorf("invalid route gateway %q: %w", o.Gateway, err)
	}
	if o.Device != "" && !ifaceRegex.MatchString(o.Device) {
		return fmt.Errorf("invalid route device %q", o.Device)
	}
	return nil
}

type OpRouteReplace struct {
	Destination     string `json:"destination"`
	Gateway         string `json:"gateway"`
	Device          string `json:"device,omitempty"`
	PreviousGateway string `json:"previous_gateway,omitempty"`
}

func (o OpRouteReplace) Kind() OpKind                   { return OpKindRouteReplace }
func (o OpRouteReplace) Target() string                 { return o.Destination }
func (o OpRouteReplace) Subsystem() string              { return "route" }
func (o OpRouteReplace) RequiredCapabilities() []string { return []string{"ip"} }
func (o OpRouteReplace) RollbackOp() Operation {
	if o.PreviousGateway != "" && o.PreviousGateway != "(no default route)" && o.PreviousGateway != "(none)" {
		return OpRouteReplace{
			Destination: o.Destination,
			Gateway:     o.PreviousGateway,
			Device:      o.Device,
		}
	}
	return OpRouteDelete{Destination: o.Destination}
}
func (o OpRouteReplace) RenderCommand() string {
	cmd := fmt.Sprintf("ip route replace %s via %s", o.Destination, o.Gateway)
	if o.Device != "" {
		cmd += " dev " + o.Device
	}
	return cmd
}
func (o OpRouteReplace) Validate() error {
	if o.Destination != "default" {
		if _, err := netip.ParsePrefix(o.Destination); err != nil {
			return fmt.Errorf("invalid route destination %q: %w", o.Destination, err)
		}
	}
	if _, err := netip.ParseAddr(o.Gateway); err != nil {
		return fmt.Errorf("invalid route gateway %q: %w", o.Gateway, err)
	}
	if o.Device != "" && !ifaceRegex.MatchString(o.Device) {
		return fmt.Errorf("invalid route device %q", o.Device)
	}
	return nil
}

type OpRouteDelete struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Device      string `json:"device,omitempty"`
}

func (o OpRouteDelete) Kind() OpKind                   { return OpKindRouteDelete }
func (o OpRouteDelete) Target() string                 { return o.Destination }
func (o OpRouteDelete) Subsystem() string              { return "route" }
func (o OpRouteDelete) RequiredCapabilities() []string { return []string{"ip"} }
func (o OpRouteDelete) RollbackOp() Operation {
	if o.Gateway != "" {
		return OpRouteAdd{Destination: o.Destination, Gateway: o.Gateway, Device: o.Device}
	}
	return nil
}
func (o OpRouteDelete) RenderCommand() string {
	cmd := fmt.Sprintf("ip route del %s", o.Destination)
	if o.Gateway != "" {
		cmd += " via " + o.Gateway
	}
	if o.Device != "" {
		cmd += " dev " + o.Device
	}
	return cmd
}
func (o OpRouteDelete) Validate() error {
	if o.Destination != "default" {
		if _, err := netip.ParsePrefix(o.Destination); err != nil {
			return fmt.Errorf("invalid route destination %q: %w", o.Destination, err)
		}
	}
	if o.Gateway != "" {
		if _, err := netip.ParseAddr(o.Gateway); err != nil {
			return fmt.Errorf("invalid route gateway %q: %w", o.Gateway, err)
		}
	}
	if o.Device != "" && !ifaceRegex.MatchString(o.Device) {
		return fmt.Errorf("invalid route device %q", o.Device)
	}
	return nil
}

// -------------------------------------------------------------- sysctl ops

type OpSysctlSet struct {
	Key           string `json:"key"`
	Value         string `json:"value"`
	PreviousValue string `json:"previous_value,omitempty"`
}

func (o OpSysctlSet) Kind() OpKind                   { return OpKindSysctlSet }
func (o OpSysctlSet) Target() string                 { return o.Key }
func (o OpSysctlSet) Subsystem() string              { return "sysctl" }
func (o OpSysctlSet) RequiredCapabilities() []string { return []string{"sysctl"} }
func (o OpSysctlSet) RollbackOp() Operation {
	prev := o.PreviousValue
	if prev == "" || prev == "disabled" || prev == "0" || prev == "false" {
		prev = "0"
	} else if prev == "enabled" || prev == "1" || prev == "true" {
		prev = "1"
	}
	return OpSysctlSet{Key: o.Key, Value: prev}
}
func (o OpSysctlSet) RenderCommand() string {
	return fmt.Sprintf("sysctl -w %s=%s", o.Key, o.Value)
}
func (o OpSysctlSet) Validate() error {
	if o.Key != "net.ipv4.ip_forward" && o.Key != "net.ipv6.conf.all.forwarding" {
		return fmt.Errorf("sysctl key %q not allowed; only forwarding tunables are supported", o.Key)
	}
	if o.Value != "0" && o.Value != "1" {
		return fmt.Errorf("sysctl value %q not allowed; only 0 or 1 permitted", o.Value)
	}
	return nil
}

// ------------------------------------------------------------ nftables ops

type OpNFTApplyTHNTable struct {
	InboundPolicy    string   `json:"inbound_policy"`
	AllowEstablished bool     `json:"allow_established"`
	AllowLoopback    bool     `json:"allow_loopback"`
	NATInterfaces    []string `json:"nat_interfaces,omitempty"`

	// LANInterface and WANInterface are the kernel names the gateway routes
	// between. They are optional because not every plan has both resolved;
	// when either is absent THN installs the table without the inter-segment
	// forwarding rules rather than guessing a direction.
	//
	// This matters more than it looks. The forward chain's policy is the same
	// drop policy the input chain uses, and a drop policy with no accept rule
	// blocks everything — including the LAN-to-WAN traffic that is the entire
	// point of the device. These fields are what make the gateway forward
	// anything at all.
	LANInterface string `json:"lan_interface,omitempty"`
	WANInterface string `json:"wan_interface,omitempty"`

	// LANSubnet is the prefix LANInterface is expected to serve. When set it
	// is matched alongside the interface name, so a host that somehow
	// acquired a second address on the LAN link cannot source forwarding
	// traffic with it.
	//
	// Empty when the segment was never determined.
	LANSubnet string `json:"lan_subnet,omitempty"`
}

func (o OpNFTApplyTHNTable) Kind() OpKind                   { return OpKindNFTApplyTHNTable }
func (o OpNFTApplyTHNTable) Target() string                 { return "table inet thn" }
func (o OpNFTApplyTHNTable) Subsystem() string              { return "nftables" }
func (o OpNFTApplyTHNTable) RequiredCapabilities() []string { return []string{"nft"} }
func (o OpNFTApplyTHNTable) RollbackOp() Operation          { return OpNFTDeleteTHNTable{} }
func (o OpNFTApplyTHNTable) RenderCommand() string          { return "nft apply table inet thn" }
func (o OpNFTApplyTHNTable) Validate() error {
	p := strings.ToLower(o.InboundPolicy)
	if p != "drop" && p != "accept" {
		return fmt.Errorf("invalid nftables inbound policy %q; must be drop or accept", o.InboundPolicy)
	}
	for _, iface := range o.NATInterfaces {
		if !ifaceRegex.MatchString(iface) {
			return fmt.Errorf("invalid NAT interface %q", iface)
		}
	}
	for field, iface := range map[string]string{"LAN": o.LANInterface, "WAN": o.WANInterface} {
		if iface != "" && !ifaceRegex.MatchString(iface) {
			return fmt.Errorf("invalid %s interface %q", field, iface)
		}
	}
	if o.LANInterface != "" && o.WANInterface != "" && o.LANInterface == o.WANInterface {
		return fmt.Errorf("LAN and WAN must not both be %q; a gateway cannot route out of its own ingress", o.LANInterface)
	}
	if o.LANSubnet != "" {
		if _, err := netip.ParsePrefix(o.LANSubnet); err != nil {
			return fmt.Errorf("invalid LAN subnet %q: %w", o.LANSubnet, err)
		}
	}
	return nil
}

// GatewayPath reports whether the operation can install forwarding rules.
//
// A caller that needs to know whether LAN-to-WAN traffic will be permitted
// asks this rather than reading the policy, because the policy alone answers
// "drop" whether or not the gateway is allowed to pass traffic.
func (o OpNFTApplyTHNTable) GatewayPath() bool {
	return o.LANInterface != "" && o.WANInterface != ""
}

type OpNFTDeleteTHNTable struct{}

func (o OpNFTDeleteTHNTable) Kind() OpKind                   { return OpKindNFTDeleteTHNTable }
func (o OpNFTDeleteTHNTable) Target() string                 { return "table inet thn" }
func (o OpNFTDeleteTHNTable) Subsystem() string              { return "nftables" }
func (o OpNFTDeleteTHNTable) RequiredCapabilities() []string { return []string{"nft"} }
func (o OpNFTDeleteTHNTable) RollbackOp() Operation          { return nil }
func (o OpNFTDeleteTHNTable) RenderCommand() string          { return "nft delete table inet thn" }
func (o OpNFTDeleteTHNTable) Validate() error                { return nil }

// --------------------------------------------------------------- qdisc ops

type OpQDiscApply struct {
	Interface         string `json:"interface"`
	Algorithm         string `json:"algorithm"`
	DownloadKbps      int    `json:"download_kbps,omitempty"`
	UploadKbps        int    `json:"upload_kbps,omitempty"`
	PreviousAlgorithm string `json:"previous_algorithm,omitempty"`
}

func (o OpQDiscApply) Kind() OpKind                   { return OpKindQDiscApply }
func (o OpQDiscApply) Target() string                 { return o.Interface }
func (o OpQDiscApply) Subsystem() string              { return "qdisc" }
func (o OpQDiscApply) RequiredCapabilities() []string { return []string{"tc"} }
func (o OpQDiscApply) RollbackOp() Operation {
	if o.PreviousAlgorithm != "" && o.PreviousAlgorithm != "(none)" {
		return OpQDiscApply{Interface: o.Interface, Algorithm: o.PreviousAlgorithm}
	}
	return OpQDiscDelete{Interface: o.Interface}
}
func (o OpQDiscApply) RenderCommand() string {
	if o.DownloadKbps > 0 || o.UploadKbps > 0 {
		return fmt.Sprintf("tc qdisc replace dev %s root %s bandwidth %dkbit upload %dkbit",
			o.Interface, o.Algorithm, o.DownloadKbps, o.UploadKbps)
	}
	return fmt.Sprintf("tc qdisc replace dev %s root %s", o.Interface, o.Algorithm)
}
func (o OpQDiscApply) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface %q", o.Interface)
	}
	switch o.Algorithm {
	case "cake", "fq_codel", "codel", "pfifo_fast":
	default:
		return fmt.Errorf("unsupported qdisc algorithm %q", o.Algorithm)
	}
	return nil
}

type OpQDiscDelete struct {
	Interface string `json:"interface"`
}

func (o OpQDiscDelete) Kind() OpKind                   { return OpKindQDiscDelete }
func (o OpQDiscDelete) Target() string                 { return o.Interface }
func (o OpQDiscDelete) Subsystem() string              { return "qdisc" }
func (o OpQDiscDelete) RequiredCapabilities() []string { return []string{"tc"} }
func (o OpQDiscDelete) RollbackOp() Operation          { return nil }
func (o OpQDiscDelete) RenderCommand() string {
	return fmt.Sprintf("tc qdisc del dev %s root", o.Interface)
}
func (o OpQDiscDelete) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface %q", o.Interface)
	}
	return nil
}

// ----------------------------------------------------------------- DNS ops

type OpDNSApply struct {
	Servers         []string `json:"servers"`
	PreviousServers []string `json:"previous_servers,omitempty"`
}

func (o OpDNSApply) Kind() OpKind      { return OpKindDNSApply }
func (o OpDNSApply) Target() string    { return strings.Join(o.Servers, ",") }
func (o OpDNSApply) Subsystem() string { return "dns" }

// RequiredCapabilities declares that applying resolvers needs a DNS service.
//
// # Why this operation claims a capability it cannot itself provide
//
// A resolver set is only in force if something is listening and answering
// queries with it. Renaming the host's resolver file, or asserting a set in a
// plan, changes nothing on its own.
//
// THN's production execution layer implements no DNS service: it neither
// generates a resolver configuration nor starts one. This operation therefore
// carries a capability requirement that no current driver can satisfy, and the
// executor refuses the plan before the backup phase rather than reporting a
// successful apply for a subsystem that was never brought up.
//
// The alternative — executing it as a no-op and reporting success — is the one
// thing this must never do. A gateway whose apply log says "committed" while
// its DNS does not resolve is worse than one that refused.
func (o OpDNSApply) RequiredCapabilities() []string { return []string{"dns"} }

func (o OpDNSApply) RollbackOp() Operation {
	if len(o.PreviousServers) > 0 {
		return OpDNSApply{Servers: o.PreviousServers}
	}
	return nil
}
func (o OpDNSApply) RenderCommand() string {
	return fmt.Sprintf("# apply resolvers %s", strings.Join(o.Servers, ", "))
}
func (o OpDNSApply) Validate() error {
	for _, s := range o.Servers {
		if _, err := netip.ParseAddr(s); err != nil {
			return fmt.Errorf("invalid DNS resolver address %q: %w", s, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------- planner bridge

// lanSubnet derives the LAN prefix the plan's firewall should match.
//
// It is read from the plan where the plan carries the information, and from
// the observation where it does not. Both orderings occur in practice: a plan
// that also assigns the LAN address states the prefix directly, and a plan
// that only installs the firewall has to fall back to what is already
// configured — otherwise the second transaction on a gateway would install a
// looser forwarding rule than the first.
//
// Deriving it here, rather than from a constant, is what keeps the forwarding
// rule and the addressing it governs from describing different segments.
func lanSubnet(p *planner.Plan, obs diff.Observed) string {
	for _, step := range p.Steps {
		if step.ID != "lan-address-add" {
			continue
		}
		for _, field := range strings.Split(step.Desired, ",") {
			if prefix, err := netip.ParsePrefix(strings.TrimSpace(field)); err == nil {
				return prefix.Masked().String()
			}
		}
	}
	for _, addr := range obs.LANAddresses {
		if prefix, err := netip.ParsePrefix(strings.TrimSpace(addr)); err == nil {
			return prefix.Masked().String()
		}
	}
	return ""
}

// obsoleteAddresses returns the addresses in a `lan-address-remove` step that
// are genuinely being removed.
//
// The step's Current field is the interface's WHOLE observed address set and
// Desired is the whole configured set, because that is what an operator needs
// to read in `thn plan`. Neither is the list of addresses to delete.
//
// Deleting everything in Current would delete the very address the desired
// state asks for — the gateway would take its own LAN address off the LAN and
// stop routing — and would roll back to it afterwards, leaving the gateway
// flapping. Only the difference is removable.
func obsoleteAddresses(current, desired string) []string {
	keep := make(map[string]bool)
	for _, a := range strings.Split(desired, ",") {
		if a = strings.TrimSpace(a); a != "" && a != "(none)" {
			keep[a] = true
		}
	}

	var out []string
	for _, a := range strings.Split(current, ",") {
		a = strings.TrimSpace(a)
		if a == "" || a == "(none)" || keep[a] {
			continue
		}
		out = append(out, a)
	}
	return out
}

// PlanToOperations converts actionable steps in a planner.Plan into structured Operations.
func PlanToOperations(p *planner.Plan, obs diff.Observed) ([]Operation, error) {
	var ops []Operation

	for _, step := range p.Steps {
		switch step.ID {
		case "lan-link-state":
			iface := obs.LANName
			if iface == "" {
				iface = step.Target
			}
			if step.Desired == "up" {
				ops = append(ops, OpLinkSetUp{Interface: iface})
			} else {
				ops = append(ops, OpLinkSetDown{Interface: iface})
			}

		case "wan-link-state":
			iface := obs.WANName
			if iface == "" {
				iface = step.Target
			}
			if step.Desired == "up" {
				ops = append(ops, OpLinkSetUp{Interface: iface})
			} else {
				ops = append(ops, OpLinkSetDown{Interface: iface})
			}

		case "lan-address-add":
			iface := obs.LANName
			if iface == "" {
				iface = step.Target
			}
			ops = append(ops, OpAddressAdd{Interface: iface, CIDR: step.Desired})

		case "lan-address-remove":
			iface := obs.LANName
			if iface == "" {
				iface = step.Target
			}
			for _, addr := range obsoleteAddresses(step.Current, step.Desired) {
				ops = append(ops, OpAddressDelete{Interface: iface, CIDR: addr})
			}

		case "default-route-add":
			ops = append(ops, OpRouteAdd{Destination: "default", Gateway: step.Desired, Device: obs.WANName})

		case "default-route-gateway":
			ops = append(ops, OpRouteReplace{
				Destination:     "default",
				Gateway:         step.Desired,
				Device:          obs.WANName,
				PreviousGateway: step.Current,
			})

		case "ip-forwarding":
			val := "1"
			if step.Desired == "0" || step.Desired == "disabled" || step.Desired == "false" {
				val = "0"
			}
			ops = append(ops, OpSysctlSet{
				Key:           "net.ipv4.ip_forward",
				Value:         val,
				PreviousValue: step.Current,
			})

		case "firewall-absent", "firewall-empty":
			policy := "drop"
			if strings.Contains(strings.ToLower(step.Desired), "accept") {
				policy = "accept"
			}
			var natIfaces []string
			if obs.WANName != "" {
				natIfaces = append(natIfaces, obs.WANName)
			}
			ops = append(ops, OpNFTApplyTHNTable{
				InboundPolicy:    policy,
				AllowEstablished: true,
				AllowLoopback:    true,
				NATInterfaces:    natIfaces,
				LANInterface:     obs.LANName,
				WANInterface:     obs.WANName,
				LANSubnet:        lanSubnet(p, obs),
			})

		case "qos-absent", "qos-algorithm":
			algo := "cake"
			if strings.HasPrefix(step.Desired, "fq_codel") {
				algo = "fq_codel"
			}
			iface := obs.WANName
			if iface == "" {
				iface = obs.LANName
			}
			ops = append(ops, OpQDiscApply{
				Interface:         iface,
				Algorithm:         algo,
				PreviousAlgorithm: step.Current,
			})

		case "resolvers":
			var servers []string
			for _, s := range strings.Split(step.Desired, ",") {
				s = strings.TrimSpace(s)
				if s != "" && s != "(none)" {
					servers = append(servers, s)
				}
			}
			var prev []string
			for _, s := range strings.Split(step.Current, ",") {
				s = strings.TrimSpace(s)
				if s != "" && s != "(none)" {
					prev = append(prev, s)
				}
			}
			if len(servers) > 0 {
				ops = append(ops, OpDNSApply{Servers: servers, PreviousServers: prev})
			}
		}
	}

	for _, op := range ops {
		if err := op.Validate(); err != nil {
			return nil, fmt.Errorf("validating planned operation %s: %w", op.Kind(), err)
		}
	}

	return ops, nil
}

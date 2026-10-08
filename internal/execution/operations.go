package execution

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/VengeTH/THN-Gateway/internal/diff"
	"github.com/VengeTH/THN-Gateway/internal/planner"
	"github.com/VengeTH/THN-Gateway/internal/qos"
	qostc "github.com/VengeTH/THN-Gateway/internal/qos/tc"
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
	OpKindTCClassApply      OpKind = "tc_class_apply"
	OpKindTCClassDelete     OpKind = "tc_class_delete"
	OpKindTCFilterApply     OpKind = "tc_filter_apply"
	OpKindTCFilterDelete    OpKind = "tc_filter_delete"
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

	// QoSClassificationRules sets packet marks for QoS traffic classes.
	QoSClassificationRules []QoSClassificationRule `json:"qos_classification_rules,omitempty"`
}

// QoSClassificationRule maps a client IP or prefix to an nftables fwmark.
type QoSClassificationRule struct {
	ClientIP string `json:"client_ip"`
	MarkHex  string `json:"mark_hex"`
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

// OpQDiscApply installs a root queue discipline on one interface, shaping one
// direction.
//
// # Why it carries a Direction rather than both rates
//
// M7.4's version of this struct carried DownloadKbps AND UploadKbps and
// rendered one discipline from both:
//
//	tc qdisc replace dev <if> root cake bandwidth <down>kbit upload <up>kbit
//
// Three things were wrong with that. `upload` is not a CAKE option. A qdisc
// shapes egress, so on a gateway the WAN's egress is the clients' UPLOAD —
// rendering the download rate there would have capped the uplink at the
// downstream rate on any host where it had succeeded. And PlanToOperations
// dropped both rates anyway, so what actually ran was an unshaped discipline
// that reported success.
//
// So this operation is now one direction on one interface. Producing the
// complete gateway shaping means emitting two of these: an upload-shaped one
// on the WAN and a download-shaped one on the LAN.
//
// # Why it refuses rather than degrades
//
// Validate rejects an apply that carries no rate for a rate-aware algorithm.
// An unshaped CAKE is not a weaker version of a shaper, it is a different
// thing: it accepts and queues packets with no ceiling, and every counter
// looks healthy. Emitting one because the rate was lost upstream would be the
// silent degradation the product spec forbids, expressed as a working
// transaction.
type OpQDiscApply struct {
	// Interface is the kernel device the discipline attaches to.
	Interface string `json:"interface"`

	// Parent is the class ID this qdisc attaches to (e.g. "1:10").
	// Empty means root.
	Parent string `json:"parent,omitempty"`

	// Handle is the qdisc handle (e.g. "10:").
	Handle string `json:"handle,omitempty"`

	// Algorithm is the discipline: "cake", "fq_codel", or "htb".
	Algorithm string `json:"algorithm"`

	// Direction is the traffic this discipline shapes.
	Direction qostc.Direction `json:"direction"`

	// Kbps is the shaped rate in kilobits per second, for this direction
	// only. It is the configured payload rate; the wire rate CAKE is given
	// accounts for framing overhead and is computed at apply time by
	// qos/tc, not stored twice.
	Kbps int `json:"kbps,omitempty"`

	// OverheadPercent is the configured framing allowance used to derive the
	// wire rate. Zero means qos.DefaultOverheadPercent.
	OverheadPercent int `json:"overhead_percent,omitempty"`

	// MTU sizes the fq_codel quantum. Zero means 1500.
	MTU int `json:"mtu,omitempty"`

	// PreviousQdisc is the baseline captured before this transaction ran.
	//
	// It is a full tc specification, not a bare algorithm name. M7.4 stored
	// PreviousAlgorithm ("cake"), which cannot restore a handle, a rate, a
	// set of classes or a filter tree — so a rollback that appeared to
	// succeed silently replaced an operator's shaping with a different one.
	//
	// Empty means the interface had a kernel default discipline, which
	// rollback restores by deleting the root qdisc.
	PreviousQdisc string `json:"previous_qdisc,omitempty"`

	// PreviousQdiscCaptured distinguishes "no discipline was there" from
	// "THN did not look".
	//
	// Without this, an absent baseline and an uncaptured one are the same
	// value, and rollback cannot tell "there was nothing to restore" from
	// "I never found out" — which is the difference between deleting a
	// default queue and destroying someone's configuration.
	PreviousQdiscCaptured bool `json:"previous_qdisc_captured,omitempty"`

	// PreviousClasses and PreviousFilters complete the baseline needed by
	// rollback. A root-only restore would erase a class hierarchy's policy.
	PreviousClasses []string `json:"previous_classes,omitempty"`
	PreviousFilters []string `json:"previous_filters,omitempty"`
}

func (o OpQDiscApply) Kind() OpKind                   { return OpKindQDiscApply }
func (o OpQDiscApply) Target() string                 { return o.Interface }
func (o OpQDiscApply) Subsystem() string              { return "qdisc" }
func (o OpQDiscApply) RequiredCapabilities() []string { return []string{"tc"} }

// Policy projects the operation onto the shaping policy qos/tc builds from.
func (o OpQDiscApply) Policy() qos.Policy {
	p := qos.Default()
	p.Enabled = true
	p.Interface = o.Interface
	p.Algorithm = qos.Algorithm(o.Algorithm)
	p.MTU = o.MTU
	p.Limits = qos.DefaultLimits()
	p.Bandwidth.OverheadPercent = o.OverheadPercent

	// Only this direction's rate is populated. The other stays zero, which
	// CakeArgs refuses to shape — so a direction typo cannot quietly shape
	// the wrong number.
	switch o.Direction {
	case qostc.DirectionUpload:
		p.Bandwidth.UploadKbps = o.Kbps
	case qostc.DirectionDownload:
		p.Bandwidth.DownloadKbps = o.Kbps
	}
	return p
}

// Args builds the tc argument vector, or returns the reason one cannot be
// built.
//
// Both drivers call this rather than formatting the command themselves, so the
// production path and the reviewable script cannot produce different
// commands. It was exactly that duplication that let M7.4 ship a driver
// rendering `upload` while the renderer emitted `uplink`.
func (o OpQDiscApply) Args() ([]string, error) {
	if o.Algorithm == "htb" {
		defaultClass := "99"
		if o.Handle != "" {
			defaultClass = strings.TrimSuffix(o.Handle, ":")
		}
		return qostc.HTBRootArgs(o.Interface, defaultClass)
	}

	if o.Parent != "" {
		handle := o.Handle
		if handle == "" {
			handle = strings.TrimPrefix(o.Parent, "1:") + ":"
		}
		if o.Algorithm == "cake" {
			isIngress := o.Direction == qostc.DirectionDownload
			return qostc.CakeLeafArgs(o.Interface, o.Parent, handle, isIngress)
		}
		return qostc.FqCodelLeafArgs(o.Interface, o.Parent, handle, o.MTU)
	}

	p := o.Policy()

	var opts []string
	var err error
	if o.Algorithm == "fq_codel" {
		opts, err = qostc.FqCodelArgs(p, o.MTU)
	} else {
		opts, err = qostc.CakeArgs(p, o.Direction, o.MTU)
	}
	if err != nil {
		return nil, err
	}
	return qostc.QDiscReplaceArgs(o.Interface, o.Algorithm, opts...)
}

// RollbackOp restores the captured baseline, or refuses to guess.
func (o OpQDiscApply) RollbackOp() Operation {
	if !o.PreviousQdiscCaptured {
		// Refusing is the whole point. Returning OpQDiscDelete here would
		// tear down an interface whose prior state nobody recorded.
		return nil
	}
	return OpTCStateRestore{Baseline: TcBaseline{
		Device:   o.Interface,
		Root:     o.PreviousQdisc,
		Classes:  append([]string(nil), o.PreviousClasses...),
		Filters:  append([]string(nil), o.PreviousFilters...),
		Captured: true,
		// The operation currently receives the root binding here. Full
		// class/filter restoration is attached by the transaction when the
		// baseline is available; this fallback remains useful for callers
		// constructing an operation directly.
	}}
}

func (o OpQDiscApply) RenderCommand() string {
	args, err := o.Args()
	if err != nil {
		return fmt.Sprintf("# no command: %v", err)
	}
	return "tc " + strings.Join(args, " ")
}

func (o OpQDiscApply) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface %q", o.Interface)
	}
	switch o.Algorithm {
	case "cake", "fq_codel", "htb":
	case "codel", "pfifo_fast":
		// Accepted for ROLLBACK only. These are what a default or legacy
		// interface may already have, and restoring one is legitimate.
		// Installing one as the requested policy is not: neither can enforce
		// a rate, so an apply of one would be a silent downgrade.
		return fmt.Errorf("algorithm %q cannot enforce a configured rate and must not be "+
			"installed by an apply; it is only valid as a rollback target", o.Algorithm)
	default:
		return fmt.Errorf("unsupported qdisc algorithm %q", o.Algorithm)
	}

	switch o.Direction {
	case qostc.DirectionUpload, qostc.DirectionDownload:
	default:
		return fmt.Errorf("a qdisc shapes one direction; direction %q is not one of upload/download",
			o.Direction)
	}

	if o.Parent == "" && o.Algorithm != "htb" && o.Kbps <= 0 {
		return fmt.Errorf("no %s rate is configured; %s has nothing to shape toward and an "+
			"unshaped discipline would report success while capping nothing",
			o.Direction, o.Algorithm)
	}

	if _, err := o.Args(); err != nil {
		return fmt.Errorf("cannot build a %s discipline: %w", o.Algorithm, err)
	}
	return nil
}

// OpQDiscReplace reinstates a previously captured qdisc specification
// verbatim.
//
// It exists because a bare algorithm name cannot restore a real hierarchy. A
// handle, a rate, a parent and a set of parameters are all part of what was
// there, and `tc qdisc replace dev X root <algo>` restores only the third.
type OpQDiscReplace struct {
	// Spec is the tc argument text captured from `tc qdisc show`, excluding
	// the leading `tc` and the `show` verb.
	Spec string `json:"spec"`
}

// OpTCStateRestore restores the complete captured traffic-control state for
// one interface.
//
// A root qdisc is only the top of a policy tree. HTB classes, leaf qdiscs and
// filters carry the per-client rates and classification. Restoring just the
// root kind would leave a gateway with a qdisc that exists but no longer
// enforces the policy that existed before THN touched it. This operation keeps
// the restore boundary at the interface while carrying the entire baseline.
type OpTCStateRestore struct {
	Baseline TcBaseline `json:"baseline"`
}

func (o OpTCStateRestore) Kind() OpKind                   { return OpKindQDiscApply }
func (o OpTCStateRestore) Target() string                 { return o.Baseline.Device }
func (o OpTCStateRestore) Subsystem() string              { return "qdisc" }
func (o OpTCStateRestore) RequiredCapabilities() []string { return []string{"tc"} }
func (o OpTCStateRestore) RollbackOp() Operation          { return nil }
func (o OpTCStateRestore) RenderCommand() string {
	if o.Baseline.Root == "" {
		return fmt.Sprintf("tc qdisc del dev %s root", o.Baseline.Device)
	}
	return "tc " + o.Baseline.Root
}
func (o OpTCStateRestore) Validate() error {
	if !o.Baseline.Captured {
		return fmt.Errorf("traffic-control baseline for %s was not captured", o.Baseline.Device)
	}
	if !ifaceRegex.MatchString(o.Baseline.Device) {
		return fmt.Errorf("invalid baseline interface %q", o.Baseline.Device)
	}
	if o.Baseline.Root == "" {
		return nil
	}
	if _, err := splitTCSpec(o.Baseline.Root); err != nil {
		return fmt.Errorf("invalid captured root qdisc: %w", err)
	}
	for _, spec := range append(append([]string{}, o.Baseline.Classes...), o.Baseline.Filters...) {
		if _, err := splitTCSpec(spec); err != nil {
			return fmt.Errorf("invalid captured traffic-control child: %w", err)
		}
	}
	return nil
}

func (o OpQDiscReplace) Kind() OpKind                   { return OpKindQDiscApply }
func (o OpQDiscReplace) Target() string                 { return targetFromSpec(o.Spec) }
func (o OpQDiscReplace) Subsystem() string              { return "qdisc" }
func (o OpQDiscReplace) RequiredCapabilities() []string { return []string{"tc"} }

// RollbackOp is nil: reinstating a captured baseline is the end of the line.
// There is nothing recorded about what that baseline replaced, because by
// construction it was the state before THN touched anything.
func (o OpQDiscReplace) RollbackOp() Operation { return nil }

func (o OpQDiscReplace) RenderCommand() string { return "tc " + o.Spec }

func (o OpQDiscReplace) Validate() error {
	args, err := o.argv()
	if err != nil {
		return err
	}
	if len(args) < 5 || args[0] != "qdisc" {
		return fmt.Errorf("captured qdisc specification is not a qdisc command: %q", o.Spec)
	}
	// Field 2 is the device, and tcSpecs.Device will have vetted it.
	if _, err := tcSpecFields(args); err != nil {
		return err
	}
	return nil
}

// argv splits the captured specification into an argument vector.
func (o OpQDiscReplace) argv() ([]string, error) {
	return splitTCSpec(o.Spec)
}

// ------------------------------------------------------------- tc class ops

// OpTCClassApply installs or replaces a traffic control class (e.g. HTB class).
type OpTCClassApply struct {
	Interface string `json:"interface"`
	Parent    string `json:"parent"`
	ClassID   string `json:"class_id"`
	RateKbps  int    `json:"rate_kbps"`
	CeilKbps  int    `json:"ceil_kbps"`
	Priority  int    `json:"priority"`
}

func (o OpTCClassApply) Kind() OpKind                   { return OpKindTCClassApply }
func (o OpTCClassApply) Target() string                 { return o.Interface }
func (o OpTCClassApply) Subsystem() string              { return "class" }
func (o OpTCClassApply) RequiredCapabilities() []string { return []string{"tc"} }
func (o OpTCClassApply) RollbackOp() Operation {
	return OpTCClassDelete{Interface: o.Interface, ClassID: o.ClassID}
}
func (o OpTCClassApply) Args() ([]string, error) {
	return qostc.HTBClassArgs(o.Interface, o.Parent, o.ClassID, o.RateKbps, o.CeilKbps, o.Priority)
}
func (o OpTCClassApply) RenderCommand() string {
	args, err := o.Args()
	if err != nil {
		return fmt.Sprintf("# invalid class: %v", err)
	}
	return "tc " + strings.Join(args, " ")
}
func (o OpTCClassApply) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface %q", o.Interface)
	}
	if o.Parent == "" || o.ClassID == "" {
		return fmt.Errorf("parent and class_id must not be empty")
	}
	_, err := o.Args()
	return err
}

// OpTCClassDelete removes an individual tc class.
type OpTCClassDelete struct {
	Interface string `json:"interface"`
	ClassID   string `json:"class_id"`
}

func (o OpTCClassDelete) Kind() OpKind                   { return OpKindTCClassDelete }
func (o OpTCClassDelete) Target() string                 { return o.Interface }
func (o OpTCClassDelete) Subsystem() string              { return "class" }
func (o OpTCClassDelete) RequiredCapabilities() []string { return []string{"tc"} }
func (o OpTCClassDelete) RollbackOp() Operation          { return nil }
func (o OpTCClassDelete) RenderCommand() string {
	return fmt.Sprintf("tc class del dev %s classid %s", o.Interface, o.ClassID)
}
func (o OpTCClassDelete) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface %q", o.Interface)
	}
	if o.ClassID == "" {
		return fmt.Errorf("class_id must not be empty")
	}
	return nil
}

// ------------------------------------------------------------ tc filter ops

// OpTCFilterApply installs or replaces a traffic control filter (e.g. fwmark or u32 match).
type OpTCFilterApply struct {
	Interface     string `json:"interface"`
	Parent        string `json:"parent"`
	Protocol      string `json:"protocol"`
	Prio          int    `json:"prio"`
	Handle        string `json:"handle,omitempty"`
	MatchKind     string `json:"match_kind"` // "fw", "src_ip", "dst_ip"
	IP            string `json:"ip,omitempty"`
	TargetClassID string `json:"target_class_id"`
}

func (o OpTCFilterApply) Kind() OpKind                   { return OpKindTCFilterApply }
func (o OpTCFilterApply) Target() string                 { return o.Interface }
func (o OpTCFilterApply) Subsystem() string              { return "filter" }
func (o OpTCFilterApply) RequiredCapabilities() []string { return []string{"tc"} }
func (o OpTCFilterApply) RollbackOp() Operation {
	return OpTCFilterDelete{Interface: o.Interface, Parent: o.Parent, Prio: o.Prio}
}
func (o OpTCFilterApply) Args() ([]string, error) {
	if o.MatchKind == "fw" {
		return qostc.FilterFwmarkArgs(o.Interface, o.Parent, o.Prio, o.Handle, o.TargetClassID)
	}
	isSrc := o.MatchKind == "src_ip"
	return qostc.FilterIPArgs(o.Interface, o.Parent, o.Prio, o.IP, isSrc, o.TargetClassID)
}
func (o OpTCFilterApply) RenderCommand() string {
	args, err := o.Args()
	if err != nil {
		return fmt.Sprintf("# invalid filter: %v", err)
	}
	return "tc " + strings.Join(args, " ")
}
func (o OpTCFilterApply) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface %q", o.Interface)
	}
	if o.Parent == "" || o.TargetClassID == "" {
		return fmt.Errorf("parent and target_class_id must not be empty")
	}
	_, err := o.Args()
	return err
}

// OpTCFilterDelete removes an individual filter.
type OpTCFilterDelete struct {
	Interface string `json:"interface"`
	Parent    string `json:"parent"`
	Prio      int    `json:"prio"`
}

func (o OpTCFilterDelete) Kind() OpKind                   { return OpKindTCFilterDelete }
func (o OpTCFilterDelete) Target() string                 { return o.Interface }
func (o OpTCFilterDelete) Subsystem() string              { return "filter" }
func (o OpTCFilterDelete) RequiredCapabilities() []string { return []string{"tc"} }
func (o OpTCFilterDelete) RollbackOp() Operation          { return nil }
func (o OpTCFilterDelete) RenderCommand() string {
	return fmt.Sprintf("tc filter del dev %s parent %s prio %d", o.Interface, o.Parent, o.Prio)
}
func (o OpTCFilterDelete) Validate() error {
	if !ifaceRegex.MatchString(o.Interface) {
		return fmt.Errorf("invalid interface %q", o.Interface)
	}
	return nil
}

// qosRates extracts the download and upload rates from a step's Desired text.
//
// The text is diff's own encoding ("cake on eth0 down=100000 up=20000
// overhead=10"), so parsing it here is not a second interpretation: it is the
// only channel by which these values reach an operation. M7.4 dropped them at
// this boundary, which is how an unshaped discipline got applied while the
// plan showed rates.
func qosRates(desired string) (down, up int) {
	for _, f := range strings.Fields(desired) {
		switch {
		case strings.HasPrefix(f, "down="):
			down = atoiOrZero(strings.TrimPrefix(f, "down="))
		case strings.HasPrefix(f, "up="):
			up = atoiOrZero(strings.TrimPrefix(f, "up="))
		}
	}
	return down, up
}

// qosOverhead extracts the framing allowance, defaulting to qos's own.
//
// A missing value is "not configured", and qos/tc substitutes the default
// rather than shaping at the payload rate.
func qosOverhead(desired string) int {
	for _, f := range strings.Fields(desired) {
		if strings.HasPrefix(f, "overhead=") {
			if v := atoiOrZero(strings.TrimPrefix(f, "overhead=")); v > 0 {
				return v
			}
		}
	}
	return qos.DefaultOverheadPercent
}

// qosMTU extracts the MTU from a step's Desired text.
//
// Zero means "not configured", and qos/tc substitutes the conventional
// default rather than guessing an interface-specific figure here.
func qosMTU(desired string) int {
	for _, f := range strings.Fields(desired) {
		if strings.HasPrefix(f, "mtu=") {
			return atoiOrZero(strings.TrimPrefix(f, "mtu="))
		}
	}
	return 0
}

type parsedClient struct {
	id       string
	ip       string
	down     int
	up       int
	priority string
}

// parseClientSpecs extracts client policies encoded in diff's desired text.
func parseClientSpecs(desired string) []parsedClient {
	var clients []parsedClient
	for _, f := range strings.Fields(desired) {
		if strings.HasPrefix(f, "client[") && strings.HasSuffix(f, "]") {
			content := strings.TrimSuffix(strings.TrimPrefix(f, "client["), "]")
			parts := strings.Split(content, ":")
			if len(parts) >= 2 {
				c := parsedClient{
					id: parts[0],
					ip: parts[1],
				}
				for _, p := range parts[2:] {
					switch {
					case strings.HasPrefix(p, "down="):
						c.down = atoiOrZero(strings.TrimPrefix(p, "down="))
					case strings.HasPrefix(p, "up="):
						c.up = atoiOrZero(strings.TrimPrefix(p, "up="))
					case strings.HasPrefix(p, "prio="):
						c.priority = strings.TrimPrefix(p, "prio=")
					}
				}
				clients = append(clients, c)
			}
		}
	}
	return clients
}

// atoiOrZero parses a decimal, treating anything unparseable as absent.
//
// A malformed rate must not become zero silently in a way that looks like a
// deliberate "unconfigured": the caller checks for a positive rate and refuses,
// which is the correct outcome for a number it could not read.
func atoiOrZero(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > 1_000_000_000 {
			return 0
		}
	}
	return n
}

func targetFromSpec(spec string) string {
	args, err := splitTCSpec(spec)
	if err != nil {
		return ""
	}
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "dev" {
			return args[i+1]
		}
	}
	return ""
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

// qosClassificationFromPlan extracts QoS client classification rules from the plan.
func qosClassificationFromPlan(p *planner.Plan) []QoSClassificationRule {
	var rules []QoSClassificationRule
	for _, s := range p.Steps {
		if s.Subsystem == "qdisc" {
			clients := parseClientSpecs(s.Desired)
			for i, c := range clients {
				markHex := fmt.Sprintf("0x%x", (i+1)*16)
				rules = append(rules, QoSClassificationRule{
					ClientIP: c.ip,
					MarkHex:  markHex,
				})
			}
			if len(rules) > 0 {
				break
			}
		}
	}
	return rules
}

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
				InboundPolicy:          policy,
				AllowEstablished:       true,
				AllowLoopback:          true,
				NATInterfaces:          natIfaces,
				LANInterface:           obs.LANName,
				WANInterface:           obs.WANName,
				LANSubnet:              lanSubnet(p, obs),
				QoSClassificationRules: qosClassificationFromPlan(p),
			})

		case "qos-absent", "qos-algorithm", "qos-rate", "qos-policy":
			algo := "cake"
			if strings.HasPrefix(step.Desired, "fq_codel") {
				algo = "fq_codel"
			}
			down, up := qosRates(step.Desired)
			overhead := qosOverhead(step.Desired)
			mtu := qosMTU(step.Desired)
			clients := parseClientSpecs(step.Desired)

			wan, lan := obs.WANName, obs.LANName
			if len(clients) == 0 {
				// Global shaping with no per-client policy: dual-interface root CAKE/FQ-CoDel.
				for _, dir := range []struct {
					name    qostc.Direction
					kbps    int
					device  string
					present bool
				}{
					{qostc.DirectionUpload, up, wan, up > 0 && wan != ""},
					{qostc.DirectionDownload, down, lan, down > 0 && lan != ""},
				} {
					if !dir.present {
						continue
					}
					ops = append(ops, OpQDiscApply{
						Interface:       dir.device,
						Algorithm:       algo,
						Direction:       dir.name,
						Kbps:            dir.kbps,
						OverheadPercent: overhead,
						MTU:             mtu,
					})
				}
			} else {
				// Phase 2: Per-client hierarchical enforcement via HTB + leaf CAKE/FQ-CoDel.
				//
				// 1. WAN interface (Upload egress: LAN -> Internet)
				if wan != "" && up > 0 {
					ops = append(ops, OpQDiscApply{
						Interface: wan,
						Algorithm: "htb",
						Direction: qostc.DirectionUpload,
						Kbps:      up,
						Handle:    "99:",
					})
					ops = append(ops, OpTCClassApply{
						Interface: wan,
						Parent:    "1:",
						ClassID:   "1:1",
						RateKbps:  up,
						CeilKbps:  up,
						Priority:  0,
					})
					// Priority 1: Management traffic (mark 0x1) directing to Class 1:1 (unrestricted)
					ops = append(ops, OpTCFilterApply{
						Interface:     wan,
						Parent:        "1:",
						Protocol:      "ip",
						Prio:          1,
						Handle:        "0x1",
						MatchKind:     "fw",
						TargetClassID: "1:1",
					})
					for i, c := range clients {
						classID := fmt.Sprintf("1:%d0", i+1)
						leafHandle := fmt.Sprintf("%d0:", i+1)
						markHex := fmt.Sprintf("0x%x", (i+1)*16)
						prioBand := qos.Priority(c.priority).HTBPrio()
						clientUp := c.up
						minUp := clientUp / 10
						if minUp < 100 {
							minUp = 100
						}

						ops = append(ops, OpTCClassApply{
							Interface: wan,
							Parent:    "1:1",
							ClassID:   classID,
							RateKbps:  minUp,
							CeilKbps:  clientUp,
							Priority:  prioBand,
						})
						ops = append(ops, OpQDiscApply{
							Interface: wan,
							Parent:    classID,
							Handle:    leafHandle,
							Algorithm: algo,
							Direction: qostc.DirectionUpload,
							Kbps:      0, // unshaped leaf mode: HTB parent controls class rate and borrowing
							MTU:       mtu,
						})
						ops = append(ops, OpTCFilterApply{
							Interface:     wan,
							Parent:        "1:",
							Protocol:      "ip",
							Prio:          10,
							Handle:        markHex,
							MatchKind:     "fw",
							TargetClassID: classID,
						})
						ops = append(ops, OpTCFilterApply{
							Interface:     wan,
							Parent:        "1:",
							Protocol:      "ip",
							Prio:          20,
							IP:            c.ip,
							MatchKind:     "src_ip",
							TargetClassID: classID,
						})
					}
					// Default class 1:99 on WAN
					ops = append(ops, OpTCClassApply{
						Interface: wan,
						Parent:    "1:1",
						ClassID:   "1:99",
						RateKbps:  100,
						CeilKbps:  up,
						Priority:  3,
					})
					ops = append(ops, OpQDiscApply{
						Interface: wan,
						Parent:    "1:99",
						Handle:    "99:",
						Algorithm: algo,
						Direction: qostc.DirectionUpload,
						Kbps:      0,
						MTU:       mtu,
					})
				}

				// 2. LAN interface (Download egress: Internet -> Clients)
				if lan != "" && down > 0 {
					ops = append(ops, OpQDiscApply{
						Interface: lan,
						Algorithm: "htb",
						Direction: qostc.DirectionDownload,
						Kbps:      down,
						Handle:    "99:",
					})
					ops = append(ops, OpTCClassApply{
						Interface: lan,
						Parent:    "1:",
						ClassID:   "1:1",
						RateKbps:  down,
						CeilKbps:  down,
						Priority:  0,
					})
					// Priority 1: Management traffic (mark 0x1) directing to Class 1:1
					ops = append(ops, OpTCFilterApply{
						Interface:     lan,
						Parent:        "1:",
						Protocol:      "ip",
						Prio:          1,
						Handle:        "0x1",
						MatchKind:     "fw",
						TargetClassID: "1:1",
					})
					for i, c := range clients {
						classID := fmt.Sprintf("1:%d0", i+1)
						leafHandle := fmt.Sprintf("%d0:", i+1)
						markHex := fmt.Sprintf("0x%x", (i+1)*16)
						prioBand := qos.Priority(c.priority).HTBPrio()
						clientDown := c.down
						minDown := clientDown / 10
						if minDown < 100 {
							minDown = 100
						}

						ops = append(ops, OpTCClassApply{
							Interface: lan,
							Parent:    "1:1",
							ClassID:   classID,
							RateKbps:  minDown,
							CeilKbps:  clientDown,
							Priority:  prioBand,
						})
						ops = append(ops, OpQDiscApply{
							Interface: lan,
							Parent:    classID,
							Handle:    leafHandle,
							Algorithm: algo,
							Direction: qostc.DirectionDownload,
							Kbps:      0, // unshaped leaf mode
							MTU:       mtu,
						})
						ops = append(ops, OpTCFilterApply{
							Interface:     lan,
							Parent:        "1:",
							Protocol:      "ip",
							Prio:          10,
							Handle:        markHex,
							MatchKind:     "fw",
							TargetClassID: classID,
						})
						ops = append(ops, OpTCFilterApply{
							Interface:     lan,
							Parent:        "1:",
							Protocol:      "ip",
							Prio:          20,
							IP:            c.ip,
							MatchKind:     "dst_ip",
							TargetClassID: classID,
						})
					}
					// Default class 1:99 on LAN
					ops = append(ops, OpTCClassApply{
						Interface: lan,
						Parent:    "1:1",
						ClassID:   "1:99",
						RateKbps:  100,
						CeilKbps:  down,
						Priority:  3,
					})
					ops = append(ops, OpQDiscApply{
						Interface: lan,
						Parent:    "1:99",
						Handle:    "99:",
						Algorithm: algo,
						Direction: qostc.DirectionDownload,
						Kbps:      0,
						MTU:       mtu,
					})
				}
			}

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

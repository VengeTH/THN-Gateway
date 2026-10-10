# Configuration Reference & Schema Guide

This document defines the configuration schema for `/etc/thn/config.yaml`, explaining every configuration key, validation invariants, development override syntax, and validation commands.

---

## 1. Canonical Configuration File (`/etc/thn/config.yaml`)

Below is the verified configuration for `heedful-dev` with the 100 Mbps Fast Ethernet development override:

```yaml
schema_version: 1
gateway:
  name: thn-gateway
  generation: 1

network:
  # Onboard Intel Gigabit NIC (enp0s31f6)
  wan: hw:7c6170fd7f34317a
  
  # USB Fast Ethernet Adapter (enx00e099001812)
  lan: hw:2c886f45ad0cb12f
  
  # LAN Gateway address and CIDR prefix
  lan_prefix: 10.77.0.1/24
  mtu: 1500

activation:
  # Mandatory: prevents remote activation without physical presence confirmation
  require_physical_presence: true

  # Development-only override for the 100 Mbps USB Ethernet adapter
  development:
    allow_fast_ethernet_lan: true
    approved_fast_ethernet_lan:
      - hw:2c886f45ad0cb12f

nat:
  enabled: true
  masquerade:
    enabled: true
    outbound: wan

firewall:
  enabled: true

# Subsystems managed externally on this host:
qos:
  enabled: false   # Managed externally via CAKE qdisc in thn-gateway-restore.service

dhcp:
  enabled: false   # Managed externally via host dnsmasq service

dns:
  enabled: false   # Managed externally via host dnsmasq service
```

---

## 2. Configuration Key Reference

### 2.1 `gateway`
- `schema_version`: Must be `1`.
- `gateway.name`: Arbitrary identifier for the gateway instance.
- `gateway.generation`: Integer tracking configuration generations. Incremented when rolling out deliberate policy revisions.

### 2.2 `network`
- `network.wan`: Stable hardware identifier (`hw:<16-char-hash>`) for the WAN interface. Must correspond to the interface connected to the upstream modem. Run `thn discover` to obtain the correct ID.
- `network.lan`: Stable hardware identifier for the LAN interface.
- `network.lan_prefix`: IPv4 address and CIDR subnet for the LAN gateway (e.g., `10.77.0.1/24`). THN configures this IP on the LAN interface.
- `network.mtu`: Maximum Transmission Unit (typically `1500` for Ethernet).

### 2.3 `activation`
- `activation.require_physical_presence`: **Must be `true`**. Setting this to `false` is rejected as a configuration validation error. It ensures root access over SSH alone is insufficient to trigger activation.
- `activation.development.allow_fast_ethernet_lan`: Boolean flag opting into the development-only sub-Gigabit LAN exception.
- `activation.development.approved_fast_ethernet_lan`: List of string identities (`hw:...` or kernel names) specifically authorized to operate at 100 Mbps.
  - *Invariant*: If `allow_fast_ethernet_lan: true`, this list **must not be empty**.
  - *Invariant*: If `allow_fast_ethernet_lan: false`, this list **must be omitted or empty**. Listing an adapter with the flag disabled is a configuration error.

### 2.4 `nat`
- `nat.enabled`: Enables IPv4 Network Address Translation.
- `nat.masquerade.enabled`: Translates source addresses of LAN traffic to the WAN interface's IP.
- `nat.masquerade.outbound`: Logical role to apply masquerade on (must be `wan`).

### 2.5 `firewall`
- `firewall.enabled`: Renders and loads stateful firewall filtering into `table inet thn`.
- `firewall.admin.port`: Administrative SSH port (defaults to `22`).
- `firewall.admin.source`: Optional list of CIDR subnets allowed to access administrative ports. If empty, administration is permitted from any source (generates an informational warning).

### 2.6 Subsystems That Must Remain Disabled (`qos`, `dhcp`, `dns`)
- `qos.enabled: false`: THN's internal QoS subsystem requires twelve separate physical-enforcement gates to be signed off on real hardware before production activation is permitted. Because CAKE is already managed by the host systemd service, leave this `false`.
- `dhcp.enabled: false`: THN does not implement an embedded DHCP server. Activation strictly blocks if this is `true`. `dnsmasq` provides DHCP leases.
- `dns.enabled: false`: THN does not implement an embedded recursive DNS resolver. Activation strictly blocks if this is `true`. `dnsmasq` provides DNS.

---

## 3. Validation Commands & Interpreting Findings

### 3.1 Static Validation
Validates YAML syntax, schema boundaries, and internal consistency in memory:

```bash
thn validate /etc/thn/config.yaml
```

### 3.2 Live Validation Against Host Hardware
Validates that the selectors declared in configuration actually resolve to physical interfaces present on the current host:

```bash
thn validate --live /etc/thn/config.yaml
```

### 3.3 Interpreting Findings

Findings are categorized into three severity levels:

| Level | Impact on Activation | Description | Action Required? |
|---|---|---|---|
| **`error`** | **BLOCKS ACTIVATION** | Schema errors, missing approved list, invalid CIDR, or role collisions. | **Must fix immediately**. Run will not proceed until resolved. |
| **`warning`** | Permitted | Advisories such as active development mode override or unrestricted admin source. | Review carefully. Acceptable if intended. |
| **`info`** | Permitted | Informational notes (e.g., noting that DHCP, DNS, or QoS are disabled). | Normal for external `dnsmasq`/CAKE deployments. |

#### Example Output on `heedful-dev`:
```
Result: PASS (0 error, 2 warning, 6 info)

  warning  activation.development  DEVELOPMENT MODE: a Fast Ethernet LAN adapter has been approved by name. LAN throughput is capped at 100 Mbps and this configuration is NOT approved for production deployment. Set allow_fast_ethernet_lan to false to restore production policy
  warning  firewall.admin.source   administration is permitted from any source address
  info     dhcp.enabled            DHCP is disabled; clients on the LAN would have to be configured statically
  info     dns.enabled             DNS is disabled; clients would have to be pointed at an external resolver
  info     qos.enabled             this document does not ask for traffic shaping; its rates and algorithm are not required
```

---

## 4. Avoiding Duplicate Ownership Conflicts

Because `heedful-dev` is already routing traffic, avoid setting up competing controllers:

1. **Firewall Ownership**: THN owns `table inet thn`. Do not attempt to merge THN's rules into the existing `table ip thn_gateway` or vice versa.
2. **DHCP Ownership**: Do not install `isc-dhcp-server` or `kea` while `dnsmasq` is running. Port 67 (UDP) can only be bound by one process per interface.
3. **DNS Ownership**: Do not enable `systemd-resolved` stub listener on `10.77.0.1:53` while `dnsmasq` is bound to port 53.
4. **QoS Ownership**: Do not set `qos.enabled: true` in `/etc/thn/config.yaml` while `/usr/local/sbin/thn-gateway-restore` is managing qdiscs.

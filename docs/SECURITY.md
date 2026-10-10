# Security Architecture, Firewall Model & Trust Boundaries

This document defines the security architecture, threat model, firewall filtering rules, management access controls, and residual security risks for **THN Gateway**.

---

## 1. Trust Boundaries & Threat Model

THN Gateway partitions the host network into distinct security domains:

```
                      [ WAN: Untrusted ]
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Input Hook (Policy: DROP)                   │
│                                                             │
│   • Established/Related: ACCEPT                             │
│   • Loopback: ACCEPT                                        │
│   • ICMP Echo: Rate-limited 10/s (PMTU & Traceroute ACCEPT) │
│   • SSH (Port 22): ACCEPT (Subject to source CIDR)          │
│   • All Other Inbound: DROP                                 │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                Forward Hook (Policy: DROP)                  │
│                                                             │
│   • Established/Related: ACCEPT                             │
│   • Invalid State: DROP                                     │
│   • Anti-Spoofing: DROP packets claiming LAN from WAN       │
│   • LAN-to-WAN (enx... -> enp...): ACCEPT                   │
│   • Unsolicited WAN-to-LAN: DROP                            │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
                      [ LAN: Semi-Trusted ]
                  (Households in ROUTER MODE)
```

### Security Domains:
1. **WAN Domain (`enp0s31f6`)**: Untrusted external network (ISP ONT). Any unsolicited inbound packet targeting the host or forwarding downstream is dropped by default.
2. **LAN Domain (`enx00e099001812`)**: Semi-trusted downstream client network. Permitted to route out to WAN; restricted from reaching host management services except authorized ports.
3. **Out-of-band Management (`wlp2s0`, `tailscale0`)**: Trusted administrative paths. SSH is permitted and isolated from customer/neighbor traffic.

---

## 2. Physical Presence Security Model

A core invariant of THN Gateway is that **remote root access alone cannot activate a gateway**:

- In `/etc/thn/config.yaml`, `activation.require_physical_presence: true` is hardcoded. Setting it to `false` is rejected as a configuration error.
- At runtime, `thn activate` requires both `--confirm` (operator authorization) and `--confirm-present` (affirmation that the operator is physically at the device console).
- **Security Rationale**: Remote network changes on edge devices carry high bricking risk. Requiring physical presence ensures an operator is on-site with local console access before altering core routing, preventing accidental self-isolation.

---

## 3. Firewall Ruleset Breakdown (`table inet thn`)

When THN renders and installs `table inet thn`, it applies the following security policies:

### 3.1 Input Hook (`type filter hook input priority filter; policy drop`)
1. **Stateful Inspection**: `ct state established,related accept` ensures reply packets return safely.
2. **Loopback Traffic**: `iifname "lo" accept` guarantees local daemon-to-daemon communication.
3. **ICMP Filtering**:
   - `destination-unreachable accept`: Essential for Path MTU Discovery (PMTUD). Blocking this causes silent connection black holes.
   - `time-exceeded accept`: Permits traceroute diagnostics.
   - `echo-request limit rate 10/second accept`: Rate-limits ping queries against amplification attacks.
4. **Administrative SSH Access**:
   - By default: `tcp dport 22 accept`.
   - Recommended: Configure `firewall.admin.source: ["100.64.0.0/10", "192.168.1.0/24"]` in `config.yaml` to restrict SSH strictly to Tailscale and local management.

### 3.2 Forward Hook (`type filter hook forward priority filter; policy drop`)
1. **Connection Tracking Return**: `ct state established,related accept`.
2. **Invalid State Drops**: `ct state invalid drop` immediately discards malformed, out-of-order, or spoofed packets.
3. **Anti-Spoofing Filter**:
   ```nft
   iifname "enp0s31f6" ip saddr 10.77.0.0/24 drop
   ```
   Prevents IP spoofing: any packet arriving on the WAN claiming a source IP from the private LAN subnet is discarded.
4. **LAN-to-WAN Forwarding**:
   ```nft
   iifname "enx00e099001812" oifname "enp0s31f6" accept
   ```
   Permits downstream clients to traverse the gateway out to the internet.
5. **WAN-to-LAN Forwarding**: Denied by the default drop policy. No unsolicited inbound connections from the internet can reach downstream client devices.

### 3.3 Postrouting NAT Hook (`type nat hook postrouting priority srcnat; policy accept`)
```nft
oifname "enp0s31f6" masquerade
```
Translates private `10.77.0.0/24` client source addresses to the WAN interface's public/ISP IP.

---

## 4. Multi-Tenant Community ISP Security

In a community gateway sharing bandwidth with neighbor households:

### 4.1 Enforce Downstream Router Mode
- If neighbor routers are configured in Access Point (AP) mode, all neighbor devices sit on the same broadcast domain as your home network.
- **Risk**: Neighbors could access local network shares, smart TVs, or cast devices.
- **Mitigation**: Require all downstream routers to be installed in **Router Mode**. The neighbor router's internal firewall isolates their household from all other households.

### 4.2 DNS & DHCP Integrity
- `dnsmasq` serves DNS on `10.77.0.1:53` and DHCP on UDP `67`.
- Downstream clients query the gateway for name resolution. If rogue DHCP servers are connected to the central switch, they could advertise malicious gateways. Ensure downstream router WAN ports are connected directly to the switch, never their LAN ports.

---

## 5. Residual Risks & Security Trade-offs

1. **Unrestricted Administration Source**: If `firewall.admin.source` is empty, SSH is accessible from any interface reaching the host (including the LAN). Ensure strong public key authentication is configured in `/etc/ssh/sshd_config` (`PasswordAuthentication no`).
2. **Fast Ethernet USB Controller Denial of Service**: The USB 10/100 adapter handles packet interrupts on the host CPU. A high packet rate flood from a malicious downstream client could cause USB controller starvation.
3. **Foreign Table Interaction**: Because THN preserves `table ip thn_gateway` and `table inet ufw`, ensure foreign tables do not contain permissive forward accept rules that negate THN's forward drop policy.

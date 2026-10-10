# Hardware, Network Topology & Interface Specifications

This document defines the physical hardware, interface assignments, IP addressing, physical wiring topology, and hardware limitations for **THN Gateway** running on the `heedful-dev` host.

---

## 1. Host System Specifications

- **Hostname**: `heedful-dev`
- **Platform**: Dell x86_64 Server (Dell Latitude E5470 / PowerEdge environment)
- **Operating System**: Ubuntu Server 24.04 LTS (Kernel 6.8+)
- **Primary Function**: Community edge gateway, NAT router, and local network boundary

---

## 2. Physical & Logical Interface Inventory

THN Gateway relies on **stable hardware identities** calculated as `hw:<sha256("ethernet\x00"+mac)>[:16]` to ensure bindings survive interface renames or USB port re-enumeration.

| Role | Kernel Device Name | Hardware MAC Address | Stable Hardware ID | Driver / Hardware Type | Negotiated Speed | Purpose |
|---|---|---|---|---|---|---|
| **WAN** | `enp0s31f6` | `7c:61:70:fd:7f:34` | `hw:7c6170fd7f34317a` | `e1000e` (Intel I219-LM) | 1000 Mbps Full Duplex | Uplink to upstream ISP router (`192.168.1.1`) |
| **LAN** | `enx00e099001812` | `00:e0:99:00:18:12` | `hw:2c886f45ad0cb12f` | USB Fast Ethernet (`0fe6:9900`) | 100 Mbps Full Duplex | Downstream local gateway (`10.77.0.1/24`) |
| **MGMT** | `wlp2s0` | (Host Wi-Fi MAC) | `hw:e82a...` | `iwlwifi` (Intel Wireless) | Variable | Out-of-band management over home Wi-Fi |
| **VPN** | `tailscale0` | N/A (Tun) | Ephemeral | Tailscale WireGuard | Virtual | Out-of-band remote SSH administration (`100.65.7.40`) |
| **Loopback** | `lo` | `00:00:00:00:00:00` | Ephemeral | Loopback virtual | N/A | Local inter-process communication |

---

## 3. Physical Wiring & Traffic Flow

The physical cable topology is strictly directional. All managed downstream clients must sit behind the LAN interface:

```
                      ┌────────────────────────────┐
                      │    PLDT / ISP ONT Router   │
                      │       (192.168.1.1/24)     │
                      └──────────────┬─────────────┘
                                     │ (Ethernet Patch Cable)
                                     ▼
                      ┌────────────────────────────┐
                      │  WAN Port: enp0s31f6       │
                      │  (192.168.1.150 via DHCP)  │
┌─────────────────────┴────────────────────────────┴──────────────────────┐
│                       THN Gateway (heedful-dev)                         │
│                                                                         │
│   • Forwarding: net.ipv4.ip_forward = 1                                 │
│   • Firewall: table inet thn (drop by default, stateful return)         │
│   • NAT: table inet thn postrouting masquerade outbound via enp0s31f6   │
│   • Gateway IP: 10.77.0.1/24                                            │
│   • DHCP/DNS: Provided by host dnsmasq service (Port 67 / Port 53)      │
│   • Out-of-band Admin: Tailscale (100.65.7.40) & Wi-Fi (wlp2s0)        │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │  LAN Port: enx00e099001812
                      │  (USB 100 Mbps Adapter)
                      ▼ (Ethernet Cable)
       ┌──────────────────────────────────────────────┐
       │         Central Unmanaged Gigabit Switch     │
       └───────┬──────────────────────────────┬───────┘
               │ (Port 1)                     │ (Port 2..N)
               ▼                              ▼
┌───────────────────────────┐  ┌───────────────────────────────┐
│     Home / Family Router  │  │        Neighbor Router        │
│   (WAN Port: 10.77.0.50)  │  │    (WAN Port: 10.77.0.100)    │
│   (ROUTER MODE: Required) │  │    (ROUTER MODE: Required)    │
│   (Local LAN: 192.168.2.x)│  │    (Local LAN: 192.168.3.x)   │
└──────────────┬────────────┘  └──────────────┬────────────────┘
               ▼                              ▼
        Family Devices                 Neighbor Devices
   (Phones, Laptops, Smart TVs)    (Household Phones, Laptops)
```

### Critical Bypass Warning
Any device plugged directly into the upstream ISP router (`192.168.1.1`) or connected to the ISP router's Wi-Fi network **completely bypasses THN Gateway**. Its traffic does not traverse `heedful-dev`, is not subject to THN firewall or shaping policies, and cannot be managed by THN.

---

## 4. Downstream Network Topology: Router Mode vs AP Mode

When distributing connectivity from the central switch to downstream routers (whether your family router or neighbor routers), **all downstream devices must operate in ROUTER MODE (NAT enabled)**:

| Architectural Requirement | ROUTER MODE (Mandatory) | AP MODE (Access Point / Bridge) |
|---|---|---|
| **DHCP Handling** | Each household router manages its own internal pool (e.g., `192.168.2.x`, `192.168.3.x`). Devices connect automatically. | THN does not run an internal DHCP server; every device would hit the switch and require either `dnsmasq` allocation or static configuration. |
| **Household Isolation** | **Complete privacy**. Neighbor households cannot see family computers, printers, or smart TVs. | **Zero isolation**. All family and neighbor devices share one broadcast domain, causing ARP chatter and security risks. |
| **Bandwidth Accountability** | **1 Household = 1 IP**. The entire household is NATed to a single IP on the `10.77.0.0/24` subnet (e.g., `10.77.0.100`). Traffic shaping is easily enforced per household. | Fragmented. A household with 10 devices appears as 10 distinct dynamic IPs and MACs. |
| **Gateway Safety** | Neighbor devices cannot probe the gateway's management interfaces. | Neighbor devices sit on the same subnet as the gateway LAN interface. |

---

## 5. Fast Ethernet USB Adapter: Technical Constraints & Residual Risks

The current LAN interface is a USB 10/100 Mbps Fast Ethernet adapter (`enx00e099001812`, USB ID `0fe6:9900`):

### 5.1 Throughput Bottleneck
- **Theoretical Line Rate**: 100 Mbps (Full Duplex: 100 Mbps transmit, 100 Mbps receive).
- **Effective Payload Cap**: With standard Ethernet framing (1518 bytes MTU), IP headers (20 bytes), and TCP headers (20 bytes), the maximum TCP throughput cannot exceed **~94.9 Mbps**.
- **Impact**: Regardless of upstream WAN bandwidth (even on a 300+ Mbps or 1 Gbps fiber uplink), all devices behind this LAN adapter share a maximum aggregated downstream bandwidth of ~94 Mbps.

### 5.2 USB Bus & CPU Interrupt Latency
- USB 2.0 Fast Ethernet controllers rely on host-polled USB endpoints rather than PCIe direct memory access (DMA).
- Under high packet-per-second load (e.g., simultaneous torrents or multiple video streams), packet processing generates significant kernel interrupt load and higher jitter than a native PCIe or USB 3.0 Gigabit NIC.

### 5.3 External CAKE Interaction
- External traffic shaping configured at $100\text{ Mbps}$ download on the host shapes upstream WAN traffic to match what the LAN adapter can physically carry.
- Do not configure shaping rates above 95 Mbps on this link, as physical buffering in the USB controller will cause packet drops before the shaping algorithm can control latency.

### 5.4 Production Upgrade Path
When deploying to production, replace `enx00e099001812` with a dedicated USB 3.0 Gigabit Ethernet adapter (e.g., Realtek RTL8153 or ASIX AX88179) or PCIe NIC:
1. Plug in the Gigabit adapter.
2. Run `thn discover` to identify its new stable ID (`hw:...`).
3. Update `network.lan` in `/etc/thn/config.yaml`.
4. Remove the `activation.development` block to restore strict production enforcement.

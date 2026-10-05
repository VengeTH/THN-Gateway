# THN M6.1/M6.2 — Disposable Linux Lab

This document defines the architecture, creation, reset, and teardown procedures for the THN Disposable Linux Lab Environment.

M6.1 added live execution. M6.2 adds end-to-end validation: proving that THN
behaves as a router inside this lab, with real packets.

Everything below is split into two kinds of work:

| Section | Who runs it |
|---------|-------------|
| **AUTOMATED BY CODE** | THN's own test suite. You run one command. |
| **MANUAL USER STEPS** | You, in a hypervisor and in a terminal. Copilot cannot do any of this. |

Nothing in this document was executed by Copilot. The commands in the MANUAL
sections are for you to run. The repository was written and its
non-privileged tests were run here; nothing else was.

---

## 1. Safety Boundary & Hard Safety Rules

1. **Production Dell/Home Server Remains Observation-Only**:
   - Live activation on the real Dell/home gateway is permanently disabled.
   - `activation.CanApply()` permanently returns `false`.
   - `ProductionDriver` permanently returns `CanApply() == false` and refuses every mutation with `ErrProductionActivationDisabled`.
   - No generic `--force` or bypass flag exists.

2. **Network Isolation**:
   - The lab LAN (`eth1` / `10.77.0.1/24`) **MUST NOT** be bridged directly into the user's physical home LAN (`192.168.1.0/24`).
   - The lab LAN is confined to an isolated host-only virtual network.

3. **THN Table Ownership**:
   - THN owns and manages `table inet thn` only.
   - Global flushes (`nft flush ruleset`) are strictly forbidden. Unrelated firewall tables survive untouched.
   - `TestEndToEndPreservesUnmanagedResources` proves this against a real kernel.

4. **Nothing here reaches a real network**:
   - The automated M6.2 suite builds the whole topology out of network namespaces that are destroyed when the test ends. The host's own interfaces are never read or written.
   - The manual path reaches only the isolated lab network. Never bridge `10.77.0.0/24` into the physical home LAN.

---

## 2. Lab VM Specification & Topology

### Specifications
- **Operating System**: Ubuntu Server 24.04 LTS (x86_64)
- **vCPU**: 2
- **Memory**: 2 GB RAM
- **Disk**: 16 GB virtual disk
- **Kernel Packages**: `iproute2`, `nftables`, `procps` (`sysctl`), `iproute2-tc` (optional)

### Network Topology

```
                  ┌──────────────────────────────────────────────┐
                  │                 HYPERVISOR                   │
                  │                                              │
                  │   ┌──────────────────────────────────────┐   │
                  │   │             THN LAB VM               │   │
                  │   │                                      │   │
  Host/NAT WAN ───┼──►│ eth0: WAN (DHCP upstream)            │   │
                  │   │                                      │   │
                  │   │ eth1: LAN (10.77.0.1/24, THN managed)│   │
                  │   └──────────────────┬───────────────────┘   │
                  │                      │                       │
                  │                      ▼                       │
                  │           Isolated Virtual Switch            │
                  │          (Disposable Lab LAN Bridge)         │
                  │                      ▲                       │
                  │                      │                       │
                  │   ┌──────────────────┴───────────────────┐   │
                  │   │          Test Client VM              │   │
                                    │   │          10.77.0.100/24              │   │
                                    │   │          default via 10.77.0.1        │   │
                                    │   └──────────────────────────────────────┘   │
                                    │                                              │
                                    │   ┌──────────────────────────────────────┐   │
                                    │   │   WAN-side test target (M6.2)        │   │
                                    │   │   10.77.250.2:18080                  │   │
                                    │   └──────────────────────────────────────┘   │
                                    └──────────────────────────────────────────────┘
                  ```

                  ### The M6.2 path being proven

                  ```
                            TEST CLIENT  10.77.0.100
                                 │
                                 ▼
                            THN LAN  10.77.0.1/24
                                 │
                                 ▼
                            FORWARDING   net.ipv4.ip_forward = 1
                                 │
                                 ▼
                            FIREWALL     table inet thn, forward policy drop
                                 │
                                 ▼
                            NAT          masquerade on the WAN interface
                                 │
                                 ▼
                            THN WAN
                                 │
                                 ▼
                       WAN-SIDE TEST TARGET  10.77.250.2:18080
                  ```

                  The target reports the source address it observed. That is what makes the NAT
                  claim real: the client leaves as `10.77.0.100` and must arrive as the gateway's
                  WAN address, not as itself.

                  ---

## 3. Lab Environment Marker

Live execution requires an explicit cryptographic and structural assertion that the target machine is a disposable test environment.

Marker location: `/etc/thn/lab-disposable-environment.json`

```json
{
  "disposable": true,
  "environment_id": "thn-disposable-lab-vm-m6.1",
  "topology": "disposable-lan",
  "wan_interface": "eth0",
  "lan_interface": "eth1",
  "lan_subnet": "10.77.0.0/24",
  "created_at": "2026-10-05T00:00:00Z"
}
```

If this file is missing, declares `"disposable": false`, or if production hardware identifiers (such as the Dell's MAC `7c:61:70:fd:7f:34` or hostname `dell-gateway`) are detected, `VerifyLabEnvironment` immediately halts with `BLOCKED`.

---

## 4. AUTOMATED BY CODE — The M6.2 Test Suite

`internal/lab` builds the whole four-point topology out of network namespaces
and runs THN's real `LinuxDriver` inside the gateway namespace. Real `ip`, real
`nft`, real `sysctl`, real netfilter, real IPv4 forwarding. Nothing is
simulated.

```bash
# On any Linux host with root, iproute2 and nftables:
sudo THN_M62_LAB=1 go test -count=1 -v -timeout 15m ./internal/lab/
```

Without `THN_M62_LAB=1` every test in that package skips with a stated reason.
A green run therefore always means the tests ran.

### What each test proves

| Test | Kind | Claim |
|------|------|-------|
| `TestEndToEndLANToWAN` | LIVE | A TCP connection from `10.77.0.100` reaches the WAN-side target through THN — and could not before the transaction ran. |
| `TestEndToEndNAT` | LIVE | The target reports seeing the gateway's WAN address, not `10.77.0.100`. |
| `TestEndToEndForwarding` | LIVE | `net.ipv4.ip_forward == 1` **and** a connection from another namespace arrives. Either fact alone proves nothing. |
| `TestWANToLANBlocked` | LIVE | The WAN side reaches the LAN client before THN's table and cannot after it, while LAN → WAN still works. |
| `TestEndToEndHealthCheck` | LIVE | With no WAN-side target the transaction fails health verification and rolls back, even though every structural check passes. |
| `TestEndToEndRollback` | LIVE | A transaction sabotaged at the firewall operation undoes link, address and forwarding — after a packet was observed crossing. |
| `TestEndToEndRollbackRestoresBaseline` | LIVE | After rollback the kernel has no address, no link, no forwarding, no table, and no traffic crosses. |
| `TestEndToEndPreservesUnmanagedResources` | LIVE | A foreign `inet lab_unmanaged` table and an unmanaged interface survive apply and rollback. |
| `TestEndToEndProductionActivationBlocked` | LIVE | `ProductionDriver.CanApply()` is `false` and every mutation is refused. |
| `TestCanonicalTopologyAddressing` and siblings | UNIT | The address plan is correct. Runs everywhere, including Windows. |

### Why the tests build their own topology

Three reasons, in order of importance:

1. **It cannot reach anything real.** Every interface lives in a namespace that
   is destroyed when the test ends. The host's own links are never read or
   written.
2. **It is deterministic.** The WAN side is a process on a fixed port inside a
   namespace, not the public Internet. No outcome depends on whether someone
   else's website was up.
3. **The interfaces are named `thnlan0` and `thnwan0`.** If they were `eth0` and
   `eth1`, every test would still pass if THN had grown a hardcoded special case
   for those two names. Role resolution has to actually work.

### Running the whole suite with the lab enabled

```bash
sudo THN_M62_LAB=1 go test -count=1 -timeout 20m ./...
```

---

## 5. MANUAL USER STEPS — Building the Lab

Everything in this section is performed by you. Copilot has no access to your
hypervisor, your VM, or your network.

### Option A: Multipass (fastest local setup)

```bash
# 1. Create the VM with two interfaces
multipass launch 24.04 --name thn-lab --cpus 2 --memory 2G --disk 16G

# 2. Install the tooling the lab needs
multipass exec thn-lab -- sudo apt-get update
multipass exec thn-lab -- sudo apt-get install -y iproute2 nftables procps iproute2-tc

# 3. Create the disposable-lab marker
multipass exec thn-lab -- sudo mkdir -p /etc/thn
multipass exec thn-lab -- sudo tee /etc/thn/lab-disposable-environment.json >/dev/null <<'EOF'
{
  "disposable": true,
  "environment_id": "thn-disposable-lab-vm-m6.1",
  "topology": "disposable-lan",
  "wan_interface": "eth0",
  "lan_interface": "eth1",
  "lan_subnet": "10.77.0.0/24",
  "created_at": "2026-10-05T00:00:00Z"
}
EOF
```

### Option B: QEMU/KVM with libvirt

```bash
# 1. Define the isolated LAN network
virsh net-define - <<EOF
<network>
  <name>thn-lab-lan</name>
  <bridge name="virbr-thn"/>
</network>
EOF
virsh net-start thn-lab-lan

# 2. Install the VM with the default network as WAN and the isolated one as LAN
virt-install \
  --name thn-lab \
  --ram 2048 \
  --vcpus 2 \
  --disk size=16 \
  --os-variant ubuntu24.04 \
  --network network=default,model=virtio \
  --network network=thn-lab-lan,model=virtio \
  --location http://archive.ubuntu.com/ubuntu/dists/noble/main/installer-amd64/

# 3. Then follow the marker step from Option A.
```

### Identifying which NIC is which

THN does not guess. Read the kernel:

```bash
ip route show default     # the interface carrying this is the WAN
ip -br addr               # the interface on the isolated network is the LAN
```

If they are not `eth0` and `eth1`, change the `wan_interface` and
`lan_interface` values in the marker. Nothing else needs editing — THN resolves
logical roles to whatever the interfaces turn out to be called.

---

## 6. MANUAL USER STEPS — The Test Client

```bash
# On the client VM:
sudo ip addr add 10.77.0.100/24 dev eth0
sudo ip link set eth0 up
sudo ip route replace default via 10.77.0.1
```

Confirm it can reach THN:

```bash
ping -c 3 10.77.0.1        # THN's LAN address
```

---

## 7. MANUAL USER STEPS — The WAN-Side Test Target

The target is a listener that reports the source address it observed. Run it on
the VM's upstream — a second VM on the default network, or a container on the VM
bound to an address the VM can route to.

```bash
# A minimal listener that prints the peer address of every connection.
python3 - <<'PY'
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 18080))
s.listen(16)
print("target listening on 0.0.0.0:18080", flush=True)
while True:
    c, addr = s.accept()
    print("connection from", addr[0], flush=True)
    c.sendall((addr[0] + "\n").encode())
    c.close()
PY
```

From the client VM, **before** THN has applied anything:

```bash
# Expected to FAIL: no forwarding, no NAT, no route to the WAN side.
curl --connect-timeout 3 http://10.77.250.2:18080/ || echo "blocked, as expected"
```

From the client VM, **after** the transaction has run:

```bash
curl --connect-timeout 3 http://10.77.250.2:18080/
# The target should print the gateway's WAN address, NOT 10.77.0.100.
```

From the WAN side, the reverse direction must fail:

```bash
curl --connect-timeout 3 http://10.77.0.100:18081/ && echo "UNEXPECTED" || echo "blocked, as expected"
```

---

## 8. Reset and Destruction Procedures

### Reset to Baseline State

To reset the networking state without destroying the VM:

```bash
# Remove only THN's table. Never `nft flush ruleset`.
sudo nft delete table inet thn 2>/dev/null || true

# Reset the LAN interface
sudo ip addr flush dev eth1
sudo ip link set dev eth1 down

# Reset kernel forwarding
sudo sysctl -w net.ipv4.ip_forward=0
```

### Destroy the Environment

```bash
# Multipass
multipass delete thn-lab
multipass purge

# Libvirt / QEMU
virsh destroy thn-lab
virsh undefine thn-lab --remove-all-storage
virsh net-destroy thn-lab-lan
virsh net-undefine thn-lab-lan
```

If a live test was interrupted, the namespaces it created are removed by the
next run. To remove them by hand:

```bash
for ns in thn-m62-gateway thn-m62-client thn-m62-wan; do
  ip netns delete "$ns" 2>/dev/null || true
done
```

---

## 9. MANUAL USER STEPS — Live Verification Commands

After executing an activation transaction inside the disposable environment, verify kernel networking state directly:

```bash
# 1. Verify link states
ip -br link show eth1
# Expected: eth1 UP

# 2. Verify address assignment
ip -br addr show eth1
# Expected: eth1 UP 10.77.0.1/24

# 3. Verify kernel forwarding
sysctl net.ipv4.ip_forward
# Expected: net.ipv4.ip_forward = 1

# 4. Verify routing table
ip route show default
# Expected: default via <WAN gateway> dev eth0

# 5. Verify THN nftables ruleset
sudo nft list table inet thn
# Expected: table inet thn with input/forward chains, the LAN→WAN accept rule,
#           and a postrouting masquerade rule naming the WAN interface.

# 6. Verify ownership: your other tables must still be there
sudo nft list tables
# Expected: everything you had before, plus inet thn. Nothing else removed.

# 7. Prove the traffic path, not the configuration
#    On the client VM:
curl --connect-timeout 3 http://10.77.250.2:18080/
#    On the WAN-side target: the connection shows the gateway's WAN address as
#    its source, not 10.77.0.100.
```

Steps 1–6 are what THN verifies structurally. Step 7 is what it verifies by
carrying a packet, and it is the only one that can fail when every other one
passes.

---

## 10. Remaining Limitations

Known and deliberate at the end of M6.2.

- **The automated suite builds its own topology in namespaces.** It proves the
  dataplane with real packets on a real kernel, but not on the VM's own NICs.
  The manual path in sections 5–9 is what covers the VM hardware.
- **The WAN side is one controlled endpoint, not the Internet.** No test depends
  on public reachability, by design.
- **No DHCP, DNS, VPN, multi-ISP or QoS.** Out of scope for this milestone.
- **The real Dell remains blocked.** M6.2 changes nothing about that and adds a
  test that says so.

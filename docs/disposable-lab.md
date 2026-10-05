# THN M6.1 — Disposable Linux Live Execution & Lab Environment

This document defines the architecture, creation, reset, and teardown procedures for the THN M6.1 Disposable Linux Lab Environment.

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
                  │   │         (DHCP / 10.77.0.x)           │   │
                  │   └──────────────────────────────────────┘   │
                  └──────────────────────────────────────────────┘
```

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

## 4. Setup Procedures

### Option A: Multipass (Fastest local setup)

```bash
# 1. Create isolated network for LAN
multipass networks

# 2. Launch THN Lab VM with two interfaces
multipass launch 24.04 --name thn-lab --cpus 2 --memory 2G --disk 16G

# 3. Create lab marker on the VM
multipass exec thn-lab -- sudo mkdir -p /etc/thn
multipass exec thn-lab -- sudo bash -c 'cat <<EOF > /etc/thn/lab-disposable-environment.json
{
  "disposable": true,
  "environment_id": "thn-disposable-lab-vm-m6.1",
  "topology": "disposable-lan",
  "wan_interface": "eth0",
  "lan_interface": "eth1",
  "lan_subnet": "10.77.0.0/24",
  "created_at": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'"
}
EOF'

# 4. Verify system packages
multipass exec thn-lab -- sudo apt-get update && sudo apt-get install -y iproute2 nftables procps
```

### Option B: QEMU/KVM with libvirt

```bash
# 1. Define isolated network (thn-lab-lan)
virsh net-define - <<EOF
<network>
  <name>thn-lab-lan</name>
  <bridge name="virbr-thn"/>
</network>
EOF
virsh net-start thn-lab-lan

# 2. Install VM attaching default (WAN) and thn-lab-lan (LAN)
virt-install \
  --name thn-lab \
  --ram 2048 \
  --vcpus 2 \
  --disk size=16 \
  --os-variant ubuntu24.04 \
  --network network=default,model=virtio \
  --network network=thn-lab-lan,model=virtio \
  --location http://archive.ubuntu.com/ubuntu/dists/noble/main/installer-amd64/
```

---

## 5. Reset and Destruction Procedures

### Reset to Baseline State

To reset the networking state without destroying the VM:

```bash
# Flush THN managed table
sudo nft delete table inet thn 2>/dev/null || true

# Reset LAN interface
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

---

## 6. Live Verification Commands

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
# Expected: table inet thn with input/forward chains and established/loopback accept rules
```

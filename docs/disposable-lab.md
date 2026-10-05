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

## 4. AUTOMATED BY CODE — The M6.2/M6.3 Live Test Suite

`internal/lab` builds the whole four-point topology out of network namespaces
and runs THN's real `LinuxDriver` inside the gateway namespace. Real `ip`, real
`nft`, real `sysctl`, real netfilter, real IPv4 forwarding. Nothing is
simulated.

```bash
# On any Linux host with root, iproute2, nftables and util-linux:
sudo THN_M62_LAB=1 go test -count=1 -v -timeout 15m ./internal/lab/
```

Without `THN_M62_LAB=1` every test in that package skips with a stated reason.
A green run therefore always means the tests ran.

### What the suite creates and destroys on its own

Created, before each test:

| Resource | Name | Where |
|---|---|---|
| Gateway namespace | `thn-m62-gateway` | root netns store, `/var/run/netns/` |
| Client namespace | `thn-m62-client` | same |
| WAN-side namespace | `thn-m62-wan` | same |
| Gateway WAN bridge | `thnwan0` (10.77.250.1/24) | gateway namespace |
| Gateway LAN bridge | `thnlan0` (10.77.0.1/24) | gateway namespace |
| veth ports | `vwan0`, `vlan0` | gateway namespace |
| Unmanaged dummy | `thnmgmt0` (10.77.99.1/24) | gateway namespace |
| Client address | `thnlan0` 10.77.0.100/24 | client namespace |
| WAN target address | `thnwan0` 10.77.250.2/24 | target namespace |
| WAN-side listener | TCP `10.77.250.2:18080` | target namespace |
| Lab marker | `<tmp>/lab-disposable-environment.json` | host temporary directory |

Routes installed before THN runs:

| Namespace | Route |
|---|---|
| gateway | `default via 10.77.250.2 dev thnwan0` |
| client | `default via 10.77.0.1 dev thnlan0` |
| WAN side | `10.77.0.0/24 via 10.77.250.1 dev thnwan0` |

That last route is the WAN side's return path for the LAN segment. It is not
decoration: without it the target could answer NATed traffic on its own
connected segment but had no route at all to `10.77.0.0/24`, so the WAN→LAN
connection would be impossible for reasons that have nothing to do with the
firewall, and the isolation test would prove nothing.

Each veth pair is **created in the namespace that keeps one of its ends**, and
only the gateway-side port is moved into the gateway:

```
in thn-m62-wan:     ip link add thnwan0 type veth peer name vwan0
in thn-m62-wan:     ip link set vwan0 netns thn-m62-gateway
in thn-m62-gateway: ip link set vwan0 master thnwan0
```

Creating both ends in the gateway and moving one away — the obvious reading of
"build the topology in the gateway" — makes the departing peer name a live
interface there for the microseconds between creation and the move. That name is
the same one the gateway's bridge already holds, and the kernel refuses the pair
with an error naming neither of the two interfaces involved:

```
ip netns exec thn-m62-gateway ip link add vwan0 type veth peer name thnwan0
RTNETLINK answers: File exists
```

This was the first real M6.3 live failure. `Topology.Validate` now refuses any
topology in which one namespace would hold the same interface name twice, and
the harness asserts after building that each namespace holds exactly the set of
links the topology declared — no more, no fewer.

Destroyed, after every test, including after a failure:

- every helper process, via a stop file the helper polls
- every namespace above, via `ip netns delete`
- the suite then **verifies** the namespaces are gone and fails the test if any
  survived, naming the one-line command that clears it

The LAN bridge deliberately starts **down and unaddressed**. That is the work
THN is about to do; a lab that arrived already configured would prove nothing
about whether the transaction configured it.

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

### What this suite does NOT cover

It proves the dataplane on a real kernel. It does **not** prove anything about
the lab VM's own NICs, its DHCP upstream, or any physical link. That path is
sections 5 to 9, and it is manual. A namespace passing is not a hardware
result.

### What a successful run looks like

Each live test logs the fact it established:

```
=== RUN   TestEndToEndLANToWAN
    disposable lab topology:
      thn-m62-client   thnlan0    10.77.0.100/24   -
      ...
    plan 1a2b3c4d5e6f7a8b carries 4 step(s): lan-link-state, lan-address-add, ip-forwarding, firewall-absent
    LAN → WAN: 10.77.0.100 reached 10.77.250.2:18080 (endpoint observed source 10.77.250.1)
--- PASS: TestEndToEndLANToWAN (12.41s)
```

The lines to look for:

| Line | Means |
|---|---|
| `carries N step(s)` | the plan was built from a real observation of the lab gateway |
| `LAN → WAN: …` | a packet crossed, from the LAN client through THN |
| `NAT: 10.77.0.100 … arrived … as 10.77.250.1` | masquerade was actually applied |
| `forwarding: … → … → …` | forwarding is on and a connection crossed anyway |
| `WAN → LAN: reachable before THN's table, blocked after it` | isolation, in both directions |
| `rollback undid N operation(s)` | compensating operations ran |
| `rollback verified against live kernel state` | the kernel really went back |
| `ownership verified: table inet lab_unmanaged …` | foreign tables survive |
| `no lab namespaces survived the run` | only emitted by CI, checking teardown from outside |

A run that ends with `--- SKIP:` on any live test has proved nothing, even if
the command exited 0. The suite skips without `THN_M62_LAB=1`; the CI step
treats a skip as a failure for exactly that reason.

### Running the whole suite with the lab enabled

```bash
sudo THN_M62_LAB=1 go test -count=1 -timeout 20m ./...
```

### If a run is interrupted

Namespaces survive a killed process. The next run removes them before building,
and the suite checks afterwards that none survived:

```bash
ip netns list | grep thn-m62 || echo "clean"
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

## 10. Limitations and status

### Live suite status

The suite has run three times on Linux. The third run built the topology
successfully and passed eight of the nine live tests, including real LAN → WAN
traffic, real forwarding, WAN → LAN isolation, health-check rollback, baseline
restoration, unmanaged-resource preservation and the production guard.

`TestEndToEndNAT` was the last failure, and it was a parser bug rather than a
missing rule: the gateway had translated 10.77.0.100 to 10.77.250.1, which only a
working masquerade rule can do.

The cause was one field. nftables renders `match.right` polymorphically — a
string for an interface name, a list for a connection-state test, an object for
a subnet — and the parser declared it a `string`:

    json: cannot unmarshal array into Go struct field
    nftMatch.nftables.rule.expr.match.right of type string

`encoding/json` fails the whole document on the first type mismatch, so one
perfectly valid `ct state established,related` rule in the `forward` chain meant
**zero rules were read from the entire table**. The NAT assertion asked what the
`postrouting` chain held and was told the kernel had no masquerade rule while it
was enforcing one. The same failure made `observe()` report the firewall as
absent, so every transaction re-planned a firewall installation.

`match.right` is now `json.RawMessage`, with a `rightString()` accessor that
yields a value only when the JSON really is a string. A non-string right is a
value the parser read, not a failure.

That exposed a second defect in the same parser. nft spells a masquerade as
`{"masquerade": null}` — a member whose value is null, because the statement
carries no operand. `encoding/json` turns a JSON null into a nil pointer before
the field's type is consulted, so a `*json.RawMessage` field could not tell that
statement from an absent one. The gateway's masquerade rule read as
`expr[1]=<unrecognised>` while the kernel was translating traffic with it.

NAT statements are now held as value-typed `json.RawMessage` and identified by
the key being present, whatever the value. A `nat` member whose `type` cannot be
read is reported with no type and is deliberately **not** counted as
masquerade, so a statement the parser could not understand cannot satisfy the
assertion.

`internal/lab/nftparse_test.go` reproduces the whole live table — all three
chains, every shape of `match.right` — because a fixture trimmed to the
masquerade rule could not have reproduced a failure that happened elsewhere in
the document.

**These fixes have not been re-run on Linux.**

Treat the first run as an experiment. If a test fails, the failure output is the
input to the next change; nothing in this repository should be adjusted to make
a failing assertion pass.

### Known limitations

- **The automated suite builds its own topology in namespaces.** It proves the
  dataplane with real packets on a real kernel, but not on the VM's own NICs.
  The manual path in sections 5–9 is what covers the VM hardware, and a passing
  namespace suite is not a hardware result.
- **The live harness disables reverse-path filtering inside its namespaces.**
  A distribution that sets `rp_filter=2` would otherwise drop the WAN→LAN probe
  as a forged source, and the isolation test would pass for the wrong reason —
  the block would be the path filter, not THN's firewall.
- **The WAN side is one controlled endpoint, not the Internet.** No test depends
  on public reachability, by design.
- **No DHCP, DNS, VPN, multi-ISP or QoS.** Out of scope for this milestone.
- **The real Dell remains blocked.** M6.2/M6.3 change nothing about that and add
  a test that says so.

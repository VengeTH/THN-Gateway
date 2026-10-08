# THN Gateway — physical deployment runbook

Target machine: **Dell E5470**. Deployment date: the first working day after
this commit.

Read this whole document before starting. The ordering is load-bearing: each
section assumes the previous one was completed and checked.

---

## 0. What you are about to do

You are about to turn a machine that is currently **your home server** into the
gateway for your home network. Those are the same box. If it goes wrong, you
lose remote access to the services running on it — Tailscale, SSH, Docker,
Cloudflare Tunnel.

Two facts make this survivable:

- THN will **not** touch Wi-Fi, Tailscale, Docker bridges, or any nftables
  table other than its own `inet thn`.
- The LAN interface is a **new** NIC with nothing on it. Nothing on the current
  system depends on it being down.

If either of those turns out to be false, stop and read
[Emergency recovery](#9-emergency-recovery).

### What THN will and will not do

| Will | Will not |
|---|---|
| Bring the LAN link up and give it the configured address | Change the WAN link's addresses |
| Enable IPv4 forwarding | Touch Wi-Fi or Tailscale |
| Install `table inet thn` with NAT and forwarding rules | Flush the whole ruleset |
| Install a root qdisc on the WAN if QoS is enabled | Touch foreign qdiscs |
| Set `net.ipv4.ip_forward` | **Run a DHCP server** |
| | **Run a DNS server** |

The last two are the important ones. THN models DHCP and DNS fully — you can
configure, validate and plan them — but the execution layer implements neither.
A configuration with `dhcp.enabled: true` **will refuse activation** rather than
report a gateway that hands out no addresses. Plan on static addressing.

---

## 1. Before touching networking

Do all of this first, from your existing working SSH session.

### 1.1 Confirm you can recover locally

- [ ] You can reach the Dell **over Tailscale** right now.
- [ ] You know the machine is reachable from a **physical console** (the
      monitor and keyboard you will be sitting at).
- [ ] The console works. Test it before you need it, not during.

> **The console is the recovery path.** If you have no working console, do not
> proceed. Everything in section 9 depends on it.

### 1.2 Confirm your remote access

- [ ] `tailscale status` — the Dell is online.
- [ ] `ssh <dell>` works.
- [ ] Record the address you are connected to: `echo $SSH_CONNECTION`

### 1.3 Record the current state

Write this to a file on your **laptop**, not the Dell. You will need it to
confirm nothing foreign was disturbed.

```bash
ssh <dell> 'bash -s' > ~/thn-baseline-$(date +%Y%m%d-%H%M%S).txt <<'EOF'
echo "=== hostname ===";        hostname
echo "=== date ===";           date -Is
echo "=== kernel ===";          uname -a
echo "=== default route ===";   ip -4 route show default
echo "=== all routes ===";      ip -4 route show
echo "=== link MACs ===";       ip -j link show | jq -r '.[] | "\(.ifname)\t\(.address)\t\(.operstate)"'
echo "=== addresses ===";       ip -4 addr show
echo "=== nft tables ===";      nft list tables
echo "=== nft ruleset ===";     nft list ruleset
echo "=== qdiscs ===";          tc -s qdisc show
echo "=== DNS ===";             resolvectl status 2>/dev/null || cat /etc/resolv.conf
echo "=== forwarding ===";      sysctl net.ipv4.ip_forward
echo "=== docker ===";          docker ps
EOF
```

Read the file. You want to be able to answer "what was there before?" without
running a command on the Dell.

### 1.4 Confirm THN's read-only view

```bash
ssh <dell> 'thn readiness --config /etc/thn/config.yaml'
```

This changes nothing. Read the blocking gates; they tell you what to fix
before the deployment session.

---

## 2. Hardware

### 2.1 Fit the NIC

- [ ] Shut the Dell down.
- [ ] Fit the second Gigabit NIC.
- [ ] Boot normally.

> **Use a Gigabit NIC.** The existing `ICS Advent USB 10/100` adapter
> (USB ID `0fe6:9900`, `cdc_ether`) is capped at 100 Mbit and is not suitable
> for the Internet connection. Prefer a USB 3.x Gigabit adapter with a chipset
> known to work on Linux — `r8152` (Realtek) and `r8152v2` are well supported;
> check `dmesg | grep -i usb` after plugging it in. THN does not care which
> adapter you use, as long as it appears as an Ethernet interface with a
> stable identity.

### 2.2 Confirm both Ethernet interfaces

```bash
thn discover
```

You should see two interfaces of kind `ethernet`, plus any wireless and tunnel
interfaces. Confirm the new one is present and has a link:

```bash
ip -j link show | jq -r '.[] | select(.link_type=="ether") | "\(.ifname)\t\(.operstate)"'
ip link show <new-nic>
```

- [ ] Both Ethernet interfaces are listed.
- [ ] The new NIC is `UP` (carrier present). **If it is `NO-CARRIER` or
      `DOWN`, plug it into the switch before continuing** — a LAN role gate
      will not be satisfied by an unplugged cable.

### 2.3 Record stable identities

```bash
ip -j link show | jq -r '.[] | "\(.ifname)\t\(.address)\t\(.ifindex)"'
```

The MAC addresses are the stable identities. Kernel names (`eth1`,
`enp0s31f6`, `enx00e099001812`) are **not** — they can change when you reorder
NICs or change BIOS settings. Record the MACs in your baseline file.

- [ ] MAC addresses recorded for both Ethernet interfaces.
- [ ] Current interfaces noted: `enp0s31f6` (existing), `wlp2s0` (wireless),
      `tailscale0`, Docker interfaces.

### 2.4 Decide WAN and LAN

Decide this by looking at the cables, not by guessing:

- [ ] **WAN** = the NIC connected (or to be connected) to the **PLDT/ONT or
      upstream router**.
- [ ] **LAN** = the **new** NIC, connected to the **switch** that serves your
      house.

The new NIC is LAN. It is the one with nothing already on it.

---

## 3. Configure the document

Edit `/etc/thn/config.yaml`.

### 3.1 Identify interfaces by MAC, not by kernel name

```yaml
network:
  wan: "hw:aa:bb:cc:dd:ee:ff"    # the MAC of the upstream-facing NIC
  lan: "hw:11:22:33:44:55:66"    # the MAC of the new NIC
```

If the document cannot be loaded, name the roles as bare strings instead
(`network.wan: wan`), which is supported but less durable.

### 3.2 Turn DHCP and DNS service OFF

```yaml
dhcp:
  enabled: false        # THN implements no DHCP server
dns:
  enabled: false        # THN implements no LAN DNS server
```

- [ ] `dhcp.enabled` is `false`.
- [ ] `dns.enabled` is `false`.

Leave the rest of the DHCP/DNS blocks alone if you like — they are validated
and inert — but the `enabled` flags must be false or activation will refuse.

### 3.3 Set the LAN address and keep the WAN gateway

```yaml
network:
  lan_prefix: "10.77.0.1/24"

routing:
  default_gateway: "<whatever step 1.3 recorded as the current default gateway>"
```

- [ ] `network.lan_prefix` does not overlap your current home network
      (currently `192.168.1.0/24` per the baseline).
- [ ] `routing.default_gateway` is the value from your baseline, so the existing
      uplink is preserved rather than replaced.

### 3.4 Address your LAN clients statically

Since there is no DHCP server, give each device a static address in the LAN
prefix with the gateway as `10.77.0.1` and an upstream resolver.

Example for a laptop on the LAN:

```
Address:   10.77.0.50
Netmask:   255.255.255.0
Gateway:   10.77.0.1
DNS:       1.1.1.1, 9.9.9.9     # your upstream resolvers, NOT 10.77.0.1
```

> The DNS servers are **not** the gateway. The gateway does not resolve
> anything. This is the most likely thing to get wrong when there is no LAN
> DNS service.

### 3.5 Validate

```bash
thn config validate /etc/thn/config.yaml
thn validate /etc/thn/config.yaml
```

- [ ] Both validate with no errors.

---

## 4. Inspect before acting

```bash
thn plan --config /etc/thn/config.yaml
thn activation inspect --config /etc/thn/config.yaml
```

Read `thn activation inspect` carefully. It lists:

- **What will change** — every mutation, by name.
- **What will not change** — the foreign resources THN will not touch.
- **Managed vs unmanaged interfaces** — confirm LAN and WAN are managed and
  `wlp2s0`, `tailscale0`, `docker0` and `br-*` are unmanaged.
- **Firewall resources** — confirm it says `table inet thn` and mentions no
  broad flush.
- **Management path safe** — this must be `true`. If it is false, the reason
  is printed and **activation will refuse**. Read it and stop.
- **DNS/DHCP resources** — confirm it says DHCP is not requested and not
  implemented.

- [ ] Every mutation in "what will change" is one you expect.
- [ ] Management path safe: **true**.
- [ ] The plan ID is recorded. It is the identity the apply is bound to.

> If management safety is false because the plan would remove the address your
> SSH session is using, that is the gate working correctly. Do not work around
> it — connect over the console instead, or adjust the plan.

---

## 5. Dry run

```bash
thn activate --config /etc/thn/config.yaml --confirm --confirm-present --dry-run
```

This authorizes the driver, runs every gate and every digest check, and applies
nothing.

- [ ] Exit code 0.
- [ ] No blocking gates.

---

## 6. Activate

Run this **from the Dell itself**, at the console if you can.

```bash
thn activate --config /etc/thn/config.yaml --confirm --confirm-present
```

It will run:

```
PREPARE -> BACKUP -> VALIDATE -> APPLY -> HEALTH_CHECK -> COMMIT
```

and report one of:

| Result | Meaning |
|---|---|
| `COMMITTED` | Applied and verified. Continue to section 7. |
| `ROLLED BACK` | A health check failed; THN undid its changes and **verified the host matches the pre-apply baseline**. The gateway is *not* running. Section 9. |
| `DEGRADED` | Rollback itself failed. **Do not retry.** Recover manually. Section 9. |
| `RECOVERY_REQUIRED` | A previous run was interrupted. Section 9. |

- [ ] Result recorded above.

> **If the SSH session drops during apply**, do not reconnect and do not retry.
> Wait, then check the journal described in section 9.

---

## 7. Post-activation verification

Verify each of these **from a device on the LAN**. THN's own health checks
confirm kernel state; these confirm the gateway actually serves traffic.

- [ ] **LAN client gets an address** — the static one from step 3.4, not
      anything from a DHCP server.
- [ ] **LAN client reaches the gateway** — `ping 10.77.0.1`.
- [ ] **LAN client reaches the Internet** — `ping 1.1.1.1` from the client.
- [ ] **NAT works** — from the client, `curl https://ifconfig.me` and confirm
      it shows your public IP.
- [ ] **Firewall blocks unsolicited WAN→LAN** — from a device on the upstream
      network, the LAN must not answer. If you cannot test this from upstream,
      note it as untested rather than assuming.
- [ ] **DNS works from the client** — using the upstream resolvers from step
      3.4. The gateway does **not** resolve names.
- [ ] **DHCP** — not applicable. There is no DHCP server.
- [ ] **Tailscale works** — `tailscale status` from your laptop.
- [ ] **SSH works** — `ssh <dell>` from your laptop.
- [ ] **Docker services healthy** — `docker ps` on the Dell.
- [ ] **Cloudflare Tunnel healthy** — check your tunnel's status page.
- [ ] **Foreign firewall resources intact** — compare against your baseline:
      ```bash
      nft list tables
      ```
      Every table in the baseline must still be present. `inet thn` is the only
      addition.
- [ ] **Foreign routes intact** — compare `ip -4 route show` against the
      baseline. Docker and Tailscale routes must be unchanged.

---

## 8. Rollback (if activation itself reported ROLLED BACK)

THN already did this. It ran the compensating operations in reverse order and
compared the host against the baseline it captured before the first mutation.
`ROLLED BACK` means that comparison **passed**.

Confirm independently:

```bash
ip -4 route show default          # compare to baseline
ip -4 addr show lan0              # should be back to what it was
sysctl net.ipv4.ip_forward        # compare to baseline
nft list tables                   # foreign tables intact
```

- [ ] All four match the baseline.

The gateway is not running. Fix the cause, then start again from section 3.

---

## 9. Emergency recovery

> **None of this depends on THN being healthy.** Every command is a normal
> Linux command run by hand. If you are reading this, assume something went
> wrong and do not try to fix it with THN first.

### 9.1 You are at the console

This is the primary path and it always works.

```bash
# What is the current state?
ip -4 route show
ip -4 addr show
sysctl net.ipv4.ip_forward
nft list tables

# Is THN's table the problem? Remove it — it is the only thing THN owns.
nft delete table inet thn

# Restore the LAN to what it was (use the baseline file)
ip addr flush dev <lan-nic>
ip addr add <previous-lan-address> dev <lan-nic>

# Restore forwarding
sysctl -w net.ipv4.ip_forward=<baseline value>

# Bring the link back up
ip link set <lan-nic> up
```

- [ ] Ping the Internet from the console machine.
- [ ] `tailscale status` shows the Dell online.
- [ ] `ssh` from your laptop works.

### 9.2 The journal says RECOVERY_REQUIRED

This means a previous `thn activate` was interrupted — the process died
mid-transaction. **THN does not know how far it got**, and refuses to guess.

The journal is at the path printed in the message, defaulting to
`<state_dir>/activation-journal.json`.

```bash
cat <journal path>
```

- [ ] Read it: it names the plan, the last phase, and the operations applied.
- [ ] Use that list to decide what to undo, **manually**, using section 9.1.
- [ ] Once the host is confirmed in a known state, remove the journal:
      ```bash
      rm <journal path>
      ```
- [ ] Re-run `thn activation inspect` before attempting activation again.

### 9.3 You lost the LAN and need to get back in

```bash
# From the console: confirm the uplink is still there.
ip -4 route show default
ping -c3 1.1.1.1
```

If forwarding and the uplink are intact, the WAN side is unaffected and Tailscale
should still work.

If the uplink is gone:

```bash
# Restore the default route from the baseline file.
ip route replace default via <baseline-gateway> dev <wan-nic>
```

- [ ] `ping 1.1.1.1` succeeds from the Dell.

### 9.4 Nuclear option

If the Dell's networking is beyond repair and you need it back as a plain home
server:

```bash
# Stop everything THN could have touched.
systemctl stop thnd 2>/dev/null

# Remove THN's firewall table. This is the only THN-owned resource.
nft delete table inet thn 2>/dev/null

# Restore addresses and routes from the baseline file, by hand.
# The baseline is the authority. Use it.
```

Then, from your laptop, restore the machine's original network configuration
from your backup of `/etc/NetworkManager/system-connections/` or equivalent.

---

## 10. Things that will refuse, and why

Do not work around any of these. Each is a gate doing its job.

| Refusal | Meaning |
|---|---|
| `physical-presence` | `--confirm-present` was not passed. Only a human at the machine can supply this. |
| `subsystems-executable` | `dhcp.enabled` or `dns.enabled` is true. THN implements neither. Set them false. |
| `management-safety` | The plan would sever SSH, remove the management IP, touch the overlay tunnel, or drop the default route. |
| `lan-identified` / `wan-present` | The role selectors match no observed interface, or the cable is out. |
| `no-role-conflicts` | Both roles resolve to the same interface, or the document and the assignment store disagree. |
| `capabilities-observed` | A required capability (`ip`, `nft`, `sysctl`, `tc`) was inferred rather than observed, i.e. not actually probed on this host. |
| `digests-fresh` | The host or the document changed after the plan was built. Re-run `thn plan`. |
| `recoverable` | An operation in the plan has no rollback. THN will not do something it cannot undo. |
| `host-readiness` | Fewer than two assignable Ethernet interfaces, or similar. |
| `config-valid` | Run `thn validate` and fix what it reports. |

---

## 11. Command reference

Read-only. Safe at any time, including over SSH.

```bash
thn readiness                       # how far this host is from an activation
thn activation verify               # the full gate set with reasons
thn activation inspect              # the exact mutations, and what is preserved
thn plan                            # the plan and its digests
thn discover                        # observed interfaces and stable identities
thn config validate <path>          # document coherence
thn validate <path>                 # subsystem validation
thn diagnostics                     # host and THN health
thn status                          # what the document asks for
```

Activation. Destructive. Requires both flags and every gate satisfied.

```bash
thn activate --confirm --confirm-present              # apply
thn activate --confirm --confirm-present --dry-run    # authorize and check, apply nothing
```

---

## 12. Final checklist

Before you leave the machine:

- [ ] Activation reported `COMMITTED`.
- [ ] Every check in section 7 passed, or is recorded as untested with a reason.
- [ ] `nft list tables` shows every baseline table plus `inet thn`, and nothing
      removed.
- [ ] `ip -4 route show` matches the baseline apart from the LAN route.
- [ ] Tailscale, SSH, Docker and Cloudflare Tunnel all healthy.
- [ ] The baseline file is saved somewhere off the Dell.
- [ ] You know where the journal file is.
- [ ] You have read section 9.
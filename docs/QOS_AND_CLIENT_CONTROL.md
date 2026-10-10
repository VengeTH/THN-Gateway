# QoS and Client Control

How THN limits a client's bandwidth, why the two directions are not
interchangeable, and how to make the gateway see devices that are hiding
behind a router or an access point.

---

## 1. What actually enforces a limit

A queue discipline (`tc`) shapes **egress** only. A packet leaves the box by
exactly one interface, and that is the only interface whose queue discipline
can hold it back.

| Direction | Where it is shaped | Interface | Egress carries |
|---|---|---|---|
| Download | LAN egress | `enx00e099001812` | internet → client |
| Upload | WAN egress | `enp0s31f6` | client → internet |

Both directions are shaped by an HTB class per client:

```
tc qdisc replace dev <iface> root handle 1: htb default 999
tc class  replace dev <iface> parent 1:1 classid 1:<n> htb rate <wire>mbit ceil <wire>mbit prio 2
tc qdisc  replace dev <iface> parent 1:<n> handle <n>: fq_codel limit 10240 flows 1024
tc filter replace dev <iface> parent 1:0 protocol ip prio 2 handle 0x100<n> fw classid 1:<n>
```

Where `<n>` is the last octet of the client's address, and `0x100<n>` is the
packet mark that identifies it (see §2).

The default class `999` is the uncapped path. It is deliberately **not** `99`:
class minors come from the last octet of a client's address, so a default of
`99` collided with the client `.99` and applied that client's limit to every
unclassified packet.

### 1.1 Why the upload filter cannot match on the source address

This is the single most important thing on this page.

By the time an upload packet reaches the WAN's egress queue, nftables
masquerade has already rewritten its source address to the gateway's WAN
address. Therefore:

```
tc filter add dev enp0s31f6 ... u32 match ip src 10.77.0.50/32 flowid 1:10
```

**matches nothing.** Nothing errors. The filter installs, the class exists, and
the client's traffic walks past both. From the operator's chair this looks like
"the upload limit does not work", and it is why several published THN scripts —
including §11.3 of `ubuntu-server-activation-guide.md` — do not limit upload at
all despite appearing to.

Upload classification goes through the **packet mark** instead, which is set
before masquerade runs:

```
nft add table inet thn_qos
nft add chain inet thn_qos thn_client_marks \
    '{ type filter hook prerouting priority mangle; policy accept; }'
nft add rule  inet thn_qos thn_client_marks ip saddr 10.77.0.50 meta mark set 0x1032
nft add rule  inet thn_qos thn_client_marks ip daddr 10.77.0.50 meta mark set 0x1032
```

The mark is `0x1000 + last octet`. It is deterministic, survives a restart, and
cannot collide with `0x1`, which THN reserves for SSH and Tailscale.

The table is `inet thn_qos`, **separate from THN's `inet thn`**. THN flushes
and rebuilds `inet thn` on every firewall apply; if the marks lived there, the
upload limits would silently disappear the next time a firewall plan was
applied.

---

## 2. Why 30 Mbps measures as 27-28

HTB counts the bytes it is handed: the IP packet **plus the 14-byte Ethernet
header**. A speed test counts only TCP payload. Shaping at exactly the
requested figure therefore always measures low.

THN raises the shaped rate by a framing allowance so the *measured* figure
lands on the requested one:

```
shaped rate = requested × (100 + overhead%) / 100, rounded up
```

| Requested | Shaped (10% allowance) | Measured |
|---|---|---|
| 10 Mbps | 11 Mbit/s | ≈ 10 Mbps |
| 30 Mbps | 33 Mbit/s | ≈ 30 Mbps |
| 50 Mbps | 55 Mbit/s | ≈ 50 Mbps |

The allowance is **rounded up**, never to nearest: undershooting the configured
rate is the failure an operator actually notices, so the shaped rate must never
land below the request.

Tune it with `THN_OVERHEAD_PERCENT`:

```bash
# Overshooting (30 set, 32 measured) -> lower it
sudo THN_OVERHEAD_PERCENT=6 /usr/local/bin/thn-client-control limit 10.77.0.50 30 both

# Undershooting still (30 set, 28 measured) -> raise it
sudo THN_OVERHEAD_PERCENT=13 /usr/local/bin/thn-client-control limit 10.77.0.50 30 both
```

Set it once for everything by editing the default at the top of
`/usr/local/bin/thn-client-control`.

> The last few percent can also be the link itself. A USB Ethernet adapter
> frequently delivers only 85-90% of Fast Ethernet line rate, and a client
> behind Wi-Fi adds another hop. Measure with a **wired** client before
> concluding the shaper is wrong.

---

## 3. Setting a limit

Limits can be one-sided. A **direction** is part of the request, not an
afterthought.

| Direction | Effect |
|---|---|
| `both` (default) | download **and** upload capped |
| `download` | download only |
| `upload` | upload only |

### 3.1 From the Web UI

Devices → the device row → **Speed limit** buttons, with the **Dir** selector
next to them (`Both` / `Down` / `Up`).

### 3.2 From the command line

```bash
sudo thn-client-control limit   10.77.0.50 30 both
sudo thn-client-control limit   10.77.0.50 30 upload
sudo thn-client-control limit   10.77.0.50 30 download
sudo thn-client-control unlimit 10.77.0.50
sudo thn-client-control status
```

### 3.3 Limits are clamped to the link

A **requested** limit is clamped to the usable ceiling, derived from the
negotiated speed of **both** interfaces rather than assumed:

```
ceiling = min(lan_speed, wan_speed) × 94%      # 100 Mbps → 94 Mbps
```

A request above it is clamped and reported. A limit above the real link is not
a limit; it is a promise the hardware cannot keep. If neither interface reports
a speed, `THN_LINK_CEIL_MBPS` (default 94) is used.

The HTB **root and its default class** are set to the negotiated **line rate**,
not to the 94%-of-line figure. The parent is the link's total budget and the
default class is the uncapped path, so setting either to the payload ceiling
would hold an unshaped client below what the cable can carry — a regression
nothing would report. Only a per-client request is clamped.

### 3.4 Limits do not survive a reboot

Traffic control is kernel state. It is re-applied by a unit that must run
**after** the host's own shaping service:

```bash
sudo cp tools/thn-client-control.sh           /usr/local/bin/thn-client-control
sudo cp tools/thn-client-control-sync.service /etc/systemd/system/
sudo chmod 755 /usr/local/bin/thn-client-control
sudo systemctl daemon-reload
sudo systemctl enable --now thn-client-control-sync.service
```

Ordering matters. `thn-gateway-restore.service` reinstalls its CAKE discipline
on the WAN root at boot; if THN's HTB does not take that root over afterwards,
every upload class is orphaned and the upload limits stop applying.

---

## 4. Seeing routers and access points on the switch

### 4.1 What the gateway can see

The gateway can only see devices on **its own Layer-2 segment**
(`network.lan_prefix`, `10.77.0.0/24` by default). Discovery reads two sources:

1. **dnsmasq leases** — `/var/lib/misc/dnsmasq.leases`. Only devices that asked
   *this* gateway for a DHCP address.
2. **The kernel neighbour table** — `/proc/net/arp`. Only devices this gateway
   has exchanged a frame with since boot.

Neither can see through a device that is routing.

| Device on the switch | What the gateway sees |
|---|---|
| Unmanaged switch | Transparent (L2 only). **Every** device behind it is visible. |
| AP in **bridge / access-point** mode | Transparent. **Every** wireless client is visible. |
| AP in **router** mode | Only the AP's own WAN address. Everything behind it is invisible. |
| Router doing NAT + its own DHCP | Only the router's WAN address. Everything behind it is invisible. |

**This is the whole answer to "why can't it see my router/AP".** A device that
is routing hides its clients by design: it rewrites their addresses, so from the
gateway's side there is exactly one host, and it is the router.

### 4.2 Step 1 — see what the gateway currently has

```bash
thn clients                       # the same inventory the UI renders
thn clients --json | less         # everything, including sources
thn interfaces                    # confirm which NIC is the LAN
sudo thn-client-control status    # recorded limits
```

And, with the trace on, why a device was included or skipped:

```bash
sudo THN_TRACE_DISCOVERY=1 thn clients
```

The trace names each source's count and the reason an entry was dropped
(`outside 10.77.0.0/24`, `not the LAN interface`, `already known`).

### 4.3 Step 2 — put the access point into bridge mode

This is the fix, and there is no substitute for it.

1. Open the AP's admin page.
2. Set its operating mode to **Access Point** / **Bridge** / **AP mode**
   (the wording varies: *Wireless Access Point*, *Bridge*, *AP*).
3. **Disable DHCP on the AP.** Two DHCP servers on one segment hand out
   conflicting leases, and clients will randomly fail to get an address.
4. Move the uplink cable from the AP's **WAN/Internet** port to a **LAN** port.
5. Give the AP's own management address a static address inside
   `10.77.0.0/24` and outside the DHCP pool.
6. Reboot the AP.

Its wireless clients now appear on `10.77.0.0/24`, receive leases from this
gateway, and are listed individually — limitable, blockable, and visible.

### 4.4 Step 3 — make idle devices answer

A device that has sent **nothing** since the gateway booted has no ARP entry.
Absent from the table looks identical on screen to not being connected, so when
a device is missing the first move is to make the network speak:

```bash
sudo thn-client-control scan                      # sweep the configured LAN
sudo thn-client-control scan 10.77.0.0/24         # or an explicit range
```

With `arp-scan` installed the sweep is a proper ARP scan and finds devices that
ignore ICMP:

```bash
sudo apt-get install -y arp-scan
```

Without it, the command falls back to a parallel ICMP sweep, which populates
the neighbour table for any device that answers. Then:

```bash
ip neigh show dev enx00e099001812
```

### 4.5 Step 4 — if a router must stay in router mode

Then be clear about what you get. The gateway will see **one** host: the
router. You can:

- **Limit the whole household as a single entity** by limiting that one
  address. This is the honest, working configuration, and it is what
  `ubuntu-server-activation-guide.md` §11.3 assumes.
- **Or route instead of NAT.** Disable NAT and DHCP on the downstream router,
  add a static route on the gateway for the downstream subnet
  (`ip route add 192.168.1.0/24 via 10.77.0.50`), and give the router a static
  address. Only then are its clients individually visible — and every one of
  them must also be routed back, or replies are lost. Expect to configure the
  router's firewall too.

There is no third option. A NATing router cannot be transparent, and pretending
otherwise produces a Devices page that is confidently incomplete.

### 4.6 Verify

```bash
thn clients
sudo thn-client-control debug
```

`debug` prints the LAN and WAN interfaces with their negotiated speeds, the
HTB classes and `fw` filters on each, the `thn_qos` mark table, the loaded
kernel modules, and the neighbour table. Every limit you set should appear as a
class on the right interface with the right rate.

---

## 5. Debugging

### 5.1 The trace

```bash
sudo THN_TRACE_DISCOVERY=1 thn clients      # Go side: why a device was skipped
sudo THN_DEBUG=1 thn-client-control <cmd>   # shell side: every tc/nft command
```

### 5.2 The log

Every action the enforcement engine takes is appended to
`/var/log/thn-client-control.log`, with the exact command and its output. A
shaping failure that leaves no trace is the failure mode the log exists to
eliminate.

```bash
sudo tail -f /var/log/thn-client-control.log
```

### 5.3 Confirm the kernel agrees

```bash
sudo thn-client-control debug
```

Look for, on **both** interfaces:

- a `qdisc htb 1:` root — the shaper exists;
- a class `1:<n>` at the rate you asked for, **raised by the framing
  allowance** — so a "30 Mbps" limit shows `33Mbit`;
- an `fw` filter with `handle 0x100<n>` — classification exists.

Reading the classes alone is not enough. A class with no filter behind it is
installed and unshaped, and it reads as success.

### 5.4 Common failures

| Symptom | Cause | Fix |
|---|---|---|
| Upload limit does nothing | Marks absent from `thn_qos` | `sudo thn-client-control limit <ip> <mbps> both` re-asserts them |
| Limits gone after `thn activate` | THN flushed `inet thn` | Rate limits are *not* in that table, so this should not happen. Block rules *are* — re-run `block` or `sync` |
| Limits gone after reboot | TC is kernel state | `sudo systemctl enable --now thn-client-control-sync.service` |
| Limits gone after restarting `thn-gateway-restore` | Host CAKE reclaims the WAN root | `sudo thn-client-control sync` |
| 30 set, 27-28 measured | Framing allowance too low, or the link itself | Raise `THN_OVERHEAD_PERCENT`; test from a **wired** client |
| 30 set, 32+ measured | Framing allowance too high | Lower `THN_OVERHEAD_PERCENT` |
| Device missing from the list | Idle since boot, or behind a NATing router | `scan`; then check §4.3 |
| Whole network missing | LAN prefix or interface misconfigured | `sudo THN_TRACE_DISCOVERY=1 thn clients` |

### 5.5 Undo everything

```bash
sudo thn-client-control revert
```

Removes THN's queue disciplines and the `thn_qos` table, then re-runs
`thn-gateway-restore.service` so the host's own CAKE discipline is put back.
The root discipline that was in place beforehand is recorded in
`/var/lib/thn/qdisc_backup.json`.

---

## 6. Reference

### Files

| Path | Contents |
|---|---|
| `/usr/local/bin/thn-client-control` | the enforcement engine |
| `/var/lib/thn/client_controls.json` | recorded limits, read by the UI |
| `/var/lib/thn/qdisc_backup.json` | the root discipline each NIC had before THN shaped anything |
| `/var/log/thn-client-control.log` | every action taken |

### Controls record

```json
{
  "10.77.0.50": {
    "download_mbps": 30,
    "upload_mbps": 10,
    "download_wire_mbit": 33,
    "upload_wire_mbit": 11,
    "direction": "both",
    "policy": "30 Mbps down / 10 Mbps up"
  }
}
```

The UI derives its label from the **rates**, not from `policy`, so the words and
the numbers cannot drift apart.

### Environment overrides

| Variable | Default | Meaning |
|---|---|---|
| `THN_LAN_IFACE` | `enx00e099001812` | downstream interface |
| `THN_WAN_IFACE` | `enp0s31f6` | uplink interface |
| `THN_LAN_PREFIX` | `10.77.0.0/24` | the segment clients live on |
| `THN_OVERHEAD_PERCENT` | `10` | framing allowance |
| `THN_LINK_EFFICIENCY_PERCENT` | `94` | share of line rate that survives as payload |
| `THN_LINK_CEIL_MBPS` | `94` | ceiling used only when no link speed is reported |
| `THN_DEBUG` | `0` | mirror the log to stderr |
| `THN_TRACE_DISCOVERY` | unset | trace client discovery |

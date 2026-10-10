#!/usr/bin/env bash
# thn-client-control: live per-client bandwidth limiting and access control.
#
# Shapes BOTH directions of a client's traffic:
#
#   download  ->  the LAN's egress   (internet -> client)
#   upload    ->  the WAN's egress   (client -> internet)
#
# ---------------------------------------------------------------------------
# Why the upload direction cannot be classified by source IP
# ---------------------------------------------------------------------------
# A queue discipline shapes EGRESS. The WAN's egress is where a client's
# upload leaves the box -- but by the time a packet reaches that qdisc,
# nftables masquerade has already rewritten its source address to the
# gateway's WAN address. A `u32 match ip src <client>` filter on the WAN
# therefore matches nothing at all, and the client's traffic walks straight
# past the class that was supposed to hold it. Nothing errors. The limit
# simply does not exist, which is exactly what "upload limiting does not
# work" looks like from the operator's chair.
#
# Upload classification therefore goes through the packet mark, which is set
# BEFORE masquerade rewrites the address:
#
#   1. a prerouting chain sets skb->mark from the client's address;
#   2. each interface's HTB classifies on that mark with an `fw` filter.
#
# The mark is 0x1000 + the last octet of the client's address. It is
# deterministic, needs no allocation table, and cannot collide with 0x1,
# which THN reserves for management traffic.
#
# The mark table is `inet thn_qos`, deliberately SEPARATE from THN's own
# `inet thn` table. THN flushes and rebuilds `inet thn` on every firewall
# apply; upload limits must not quietly vanish when it does.
#
# ---------------------------------------------------------------------------
# Why the shaped rate is higher than the requested rate
# ---------------------------------------------------------------------------
# HTB counts the bytes it is handed: the IP packet plus the 14-byte Ethernet
# header. A speed test counts only TCP payload. Shaping at exactly the
# requested figure therefore measures low -- 30 Mbps reads as roughly 27-28.
# THN_OVERHEAD_PERCENT raises the shaped rate so the measured figure lands on
# the requested one. Lower it (THN_OVERHEAD_PERCENT=6) if it overshoots.
set -uo pipefail

# ── configuration ───────────────────────────────────────────────────────────
# Every value is overridable from the environment, so one script serves a
# 100 Mbps Fast Ethernet lab and a gigabit production link without edits.
LAN_IFACE="${THN_LAN_IFACE:-enx00e099001812}"
WAN_IFACE="${THN_WAN_IFACE:-enp0s31f6}"
LAN_PREFIX="${THN_LAN_PREFIX:-10.77.0.0/24}"

# Framing allowance, in percent. See the header note.
OVERHEAD_PERCENT="${THN_OVERHEAD_PERCENT:-10}"

# Share of the negotiated link speed that survives as TCP payload. Fast
# Ethernet carries about 94 Mbps of its 100 Mbps line rate.
LINK_EFFICIENCY_PERCENT="${THN_LINK_EFFICIENCY_PERCENT:-94}"

# Ceiling used only when neither interface reports a speed.
LINK_CEIL_FALLBACK_MBPS="${THN_LINK_CEIL_MBPS:-94}"

STATE_DIR="${THN_STATE_DIR:-/var/lib/thn}"
STATE_FILE="${STATE_DIR}/client_controls.json"
QDISC_BACKUP="${STATE_DIR}/qdisc_backup.json"
LOG_FILE="${THN_LOG_FILE:-/var/log/thn-client-control.log}"
DEBUG="${THN_DEBUG:-0}"

# HTB's default class. It must sit outside the range a client can be given:
# class minors come from the last octet of the client's address, so a default
# of 99 -- which the previous version used -- collided with the client .99 and
# then applied that client's limit to every unclassified packet.
HTB_DEFAULT_MINOR=999

# The nftables table and chain this script owns outright.
NFT_FAMILY="inet"
NFT_TABLE="thn_qos"
NFT_CHAIN="thn_client_marks"

mkdir -p "${STATE_DIR}" 2>/dev/null || true

# ── logging ─────────────────────────────────────────────────────────────────
# Every action is recorded with the command that was run and what it said. A
# shaping failure that leaves no trace is the failure mode this script exists
# to eliminate, so there is no silent path through it.
log() {
    local line
    line="$(date -Is) $*"
    printf '%s\n' "${line}" >> "${LOG_FILE}" 2>/dev/null || true
    if [[ "${DEBUG}" == "1" || "${DEBUG}" == "true" ]]; then
        printf '%s\n' "${line}" >&2
    fi
}
info() { log "INFO  $*"; printf '%s\n' "$*"; }
warn() { log "WARN  $*"; printf 'WARNING: %s\n' "$*" >&2; }
fail() { log "ERROR $*"; printf 'ERROR: %s\n' "$*" >&2; }
die()  { fail "$*"; exit 1; }
dbg()  {
    if [[ "${DEBUG}" == "1" || "${DEBUG}" == "true" ]]; then
        log "DEBUG $*"
    fi
    return 0
}

# ── external command wrappers ───────────────────────────────────────────────
run_tc() {
    local out
    dbg "tc $*"
    if ! out="$(tc "$@" 2>&1)"; then
        fail "tc $* -> ${out}"
        return 1
    fi
    [[ -n "${out}" ]] && dbg "tc $* -> ${out}"
    return 0
}

run_nft() {
    local out
    dbg "nft $*"
    if ! out="$(nft "$@" 2>&1)"; then
        fail "nft $* -> ${out}"
        return 1
    fi
    [[ -n "${out}" ]] && dbg "nft $* -> ${out}"
    return 0
}

try_tc()  { dbg "tc $* (best effort)"; tc "$@" >/dev/null 2>&1 || true; }
try_nft() { dbg "nft $* (best effort)"; nft "$@" >/dev/null 2>&1 || true; }

# ── link facts ──────────────────────────────────────────────────────────────
ensure_state() {
    mkdir -p "${STATE_DIR}"
    [[ -f "${STATE_FILE}" ]] || printf '{}\n' > "${STATE_FILE}"
    [[ -f "${QDISC_BACKUP}" ]] || printf '{}\n' > "${QDISC_BACKUP}"
}

iface_speed_mbps() {
    local speed
    speed="$(cat "/sys/class/net/$1/speed" 2>/dev/null || true)"
    if [[ "${speed}" =~ ^[0-9]+$ ]] && (( speed > 0 )); then
        printf '%s' "${speed}"
    fi
}

# link_ceiling_mbps: the highest payload rate a client may be given, derived
# from the slowest hop rather than assumed. A limit above the real link is not
# a limit; it is a promise the hardware cannot keep.
link_ceiling_mbps() {
    local s ceiling=""
    for s in "$(iface_speed_mbps "${LAN_IFACE}")" "$(iface_speed_mbps "${WAN_IFACE}")"; do
        [[ -z "${s}" ]] && continue
        local c=$(( s * LINK_EFFICIENCY_PERCENT / 100 ))
        if [[ -z "${ceiling}" ]] || (( c < ceiling )); then ceiling="${c}"; fi
    done
    [[ -z "${ceiling}" ]] && ceiling="${LINK_CEIL_FALLBACK_MBPS}"
    printf '%s' "${ceiling}"
}

# link_line_mbps: the negotiated line rate of the slowest hop.
#
# This is what the HTB root and its default class are set to, and it is
# deliberately NOT the payload ceiling. The parent class is the link's total
# budget and the default class is the uncapped path; setting either to the
# 94%-of-line payload figure would throttle an unshaped client below what the
# cable can actually carry -- a regression nobody asked for and nothing
# reports. Only a per-client *request* is clamped to the payload ceiling.
link_line_mbps() {
    local s line=""
    for s in "$(iface_speed_mbps "${LAN_IFACE}")" "$(iface_speed_mbps "${WAN_IFACE}")"; do
        [[ -z "${s}" ]] && continue
        if [[ -z "${line}" ]] || (( s < line )); then line="${s}"; fi
    done
    [[ -z "${line}" ]] && line="${LINK_CEIL_FALLBACK_MBPS}"
    printf '%s' "${line}"
}

# wire_mbit: the shaped rate, rounded UP.
#
# Up, not to nearest: undershooting the configured rate is the failure the
# operator actually notices ("I asked for 30 and got 27"), so the shaped rate
# must never land below the request.
wire_mbit() {
    printf '%s' $(( ($1 * (100 + OVERHEAD_PERCENT) + 99) / 100 ))
}

# class_minor_for_ip: a stable HTB class minor for a client.
class_minor_for_ip() {
    local last="${1##*.}"
    [[ "${last}" =~ ^[0-9]+$ ]] || return 1
    (( last >= 2 && last <= 254 )) || return 1
    printf '%s' "${last}"
}

mark_for_minor() { printf '0x%x' $(( 0x1000 + $1 )); }

ip_in_lan() {
    python3 - "$1" "$2" <<'PY'
import ipaddress, sys
try:
    addr = ipaddress.ip_address(sys.argv[1])
    net = ipaddress.ip_network(sys.argv[2], strict=False)
except ValueError:
    sys.exit(1)
sys.exit(0 if addr in net else 1)
PY
}

# ── state file ──────────────────────────────────────────────────────────────
# Writes go through os.replace so the file is never observed half-written by
# the Web UI, which reads it on every page load.
state_get() {
    python3 - "${STATE_FILE}" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    data = {}
print(json.dumps(data.get(sys.argv[2]) or {}))
PY
}

state_write_payload() {
    python3 - "${STATE_FILE}" "$1" "$2" "$3" <<'PY'
import json, os, sys, tempfile
path, ip, payload, merge = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "merge"
try:
    with open(path) as f:
        data = json.load(f)
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
new = json.loads(payload)
rec = (data.get(ip) or {}) if merge else {}
rec.update(new)
if rec:
    data[ip] = rec
else:
    data.pop(ip, None)
d = os.path.dirname(path) or "."
fd, tmp = tempfile.mkstemp(dir=d)
with os.fdopen(fd, "w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
os.replace(tmp, path)
PY
}

# state_set <ip> <json-object>   -- replaces the record; {} removes it.
state_set() { state_write_payload "$1" "$2" replace; }
# state_merge <ip> <json-object> -- adds fields, keeping the existing ones.
state_merge() { state_write_payload "$1" "$2" merge; }
state_clear() { printf '{}\n' > "${STATE_FILE}"; }

is_blocked() {
    python3 -c 'import json,sys
try:
    d = json.loads(sys.argv[1] or "{}")
except Exception:
    d = {}
sys.exit(0 if d.get("blocked") else 1)' "$(state_get "$1")" 2>/dev/null
}

policy_label() {
    local down="$1" up="$2"
    if [[ -n "${down}" && -n "${up}" ]]; then
        printf '%s Mbps down / %s Mbps up' "${down}" "${up}"
    elif [[ -n "${down}" ]]; then
        printf '%s Mbps down only' "${down}"
    elif [[ -n "${up}" ]]; then
        printf '%s Mbps up only' "${up}"
    else
        printf 'Default (Uncapped)'
    fi
}

# ── queue disciplines ───────────────────────────────────────────────────────
# backup_root_qdisc records what was on an interface before this script
# replaced it. The host installs CAKE on the WAN from
# thn-gateway-restore.service, and taking the WAN root over for HTB is a real
# change, not a no-op, so it is recorded rather than assumed away.
backup_root_qdisc() {
    local iface="$1" spec
    if python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    d = {}
sys.exit(0 if d.get(sys.argv[2]) else 1)' "${QDISC_BACKUP}" "${iface}" 2>/dev/null; then
        return 0
    fi

    spec="$(tc qdisc show dev "${iface}" 2>/dev/null | head -1 || true)"
    python3 - "${QDISC_BACKUP}" "${iface}" "${spec}" <<'PY'
import json, os, sys, tempfile
path, iface, spec = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path) as f:
        data = json.load(f)
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}
data[iface] = spec
d = os.path.dirname(path) or "."
fd, tmp = tempfile.mkstemp(dir=d)
with os.fdopen(fd, "w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
os.replace(tmp, path)
PY
    dbg "recorded existing root qdisc on ${iface}: ${spec:-<none>}"
}

# ensure_htb_root <iface> <line-mbps>
#
# The argument is the link's NEGOTIATED line rate, not the payload ceiling.
# The parent class is the link's total budget and the default class is the
# uncapped path; setting either to the 94%-of-line payload figure would hold an
# unshaped client below what the cable can carry. Only a per-client request is
# clamped to the payload ceiling.
ensure_htb_root() {
    local iface="$1" ceiling="$2"

    if tc qdisc show dev "${iface}" 2>/dev/null | grep -q 'qdisc htb 1:'; then
        dbg "${iface}: HTB root already installed"
    else
        backup_root_qdisc "${iface}"
        info "Installing HTB root on ${iface} (line ceiling ${ceiling} Mbps)"
        run_tc qdisc replace dev "${iface}" root handle 1: htb default "${HTB_DEFAULT_MINOR}" || return 1
        run_tc class replace dev "${iface}" parent 1: classid 1:1 \
            htb rate "${ceiling}mbit" ceil "${ceiling}mbit" prio 0 || return 1
    fi

    # The default class is re-asserted on every call so its ceiling tracks the
    # link as it is now: an uncapped client must be able to use the whole line.
    run_tc class replace dev "${iface}" parent 1:1 classid "1:${HTB_DEFAULT_MINOR}" \
        htb rate "${ceiling}mbit" ceil "${ceiling}mbit" prio 3 || return 1
    run_tc qdisc replace dev "${iface}" parent "1:${HTB_DEFAULT_MINOR}" \
        handle "${HTB_DEFAULT_MINOR}:" fq_codel limit 10240 flows 1024 quantum 1514 || return 1
    return 0
}

# ── packet marks (how upload is classified) ─────────────────────────────────
ensure_mark_table() {
    nft list table "${NFT_FAMILY}" "${NFT_TABLE}" >/dev/null 2>&1 \
        || run_nft add table "${NFT_FAMILY}" "${NFT_TABLE}" || return 1

    nft list chain "${NFT_FAMILY}" "${NFT_TABLE}" "${NFT_CHAIN}" >/dev/null 2>&1 \
        || run_nft add chain "${NFT_FAMILY}" "${NFT_TABLE}" "${NFT_CHAIN}" \
               '{ type filter hook prerouting priority mangle; policy accept; }' || return 1
    return 0
}

# rebuild_marks regenerates the whole mark chain from the state file.
#
# Regenerated rather than patched: a mark left behind for a client whose limit
# was removed is a client still pinned into a class, and incremental edits are
# how that happens. The chain is small, so a rebuild is cheap and always
# matches what the state file says.
rebuild_marks() {
    ensure_mark_table \
        || { warn "packet-mark table unavailable; upload limits cannot be enforced"; return 1; }
    run_nft flush chain "${NFT_FAMILY}" "${NFT_TABLE}" "${NFT_CHAIN}" || return 1

    local ip mark
    while IFS=' ' read -r ip mark; do
        [[ -z "${ip}" ]] && continue
        run_nft add rule "${NFT_FAMILY}" "${NFT_TABLE}" "${NFT_CHAIN}" \
            ip saddr "${ip}" meta mark set "${mark}" || true
        run_nft add rule "${NFT_FAMILY}" "${NFT_TABLE}" "${NFT_CHAIN}" \
            ip daddr "${ip}" meta mark set "${mark}" || true
    done < <(python3 - "${STATE_FILE}" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    data = {}
for ip in sorted(data):
    if ip.startswith("__"):
        continue
    rec = data[ip] or {}
    if not (rec.get("download_mbps") or rec.get("upload_mbps")):
        continue
    try:
        last = int(ip.rsplit(".", 1)[-1])
    except ValueError:
        continue
    if 2 <= last <= 254:
        print(ip, hex(0x1000 + last))
PY
)
    return 0
}

# apply_shaper <iface> <class-minor> <wire-mbit>
apply_shaper() {
    local iface="$1" minor="$2" wire="$3" classid mark
    classid="1:${minor}"
    mark="$(mark_for_minor "${minor}")"

    run_tc class replace dev "${iface}" parent 1:1 classid "${classid}" \
        htb rate "${wire}mbit" ceil "${wire}mbit" prio 2 || return 1
    run_tc qdisc replace dev "${iface}" parent "${classid}" handle "${minor}:" \
        fq_codel limit 10240 flows 1024 quantum 1514 || return 1
    run_tc filter replace dev "${iface}" parent 1:0 protocol ip prio 2 \
        handle "${mark}" fw classid "${classid}" || return 1
    dbg "${iface}: class ${classid} at ${wire}mbit, classified by mark ${mark}"
    return 0
}

# remove_shaper <iface> <class-minor>
remove_shaper() {
    local iface="$1" minor="$2" classid mark
    classid="1:${minor}"
    mark="$(mark_for_minor "${minor}")"
    try_tc filter del dev "${iface}" parent 1:0 protocol ip prio 2 handle "${mark}" fw
    try_tc qdisc del dev "${iface}" parent "${classid}"
    try_tc class del dev "${iface}" classid "${classid}"
}

cmd_limit() {
    local ip="${1:-}"
    local mbps="${2:-}"
    local direction="${3:-both}"

    [[ -n "${ip}" && -n "${mbps}" ]] \
        || die "Usage: $0 limit <ip> <mbps> [both|upload|download]"
    [[ "${mbps}" =~ ^[0-9]+$ ]] \
        || die "Rate must be a whole number of Mbps, got '${mbps}'"
    (( mbps > 0 )) || die "Rate must be greater than zero"

    case "${direction}" in
        both|upload|download) ;;
        "") direction="both" ;;
        *) die "Direction must be 'both', 'upload' or 'download', got '${direction}'" ;;
    esac

    ip_in_lan "${ip}" "${LAN_PREFIX}" \
        || die "${ip} is outside the LAN network ${LAN_PREFIX}; a limit there would be invisible"

    local minor
    minor="$(class_minor_for_ip "${ip}")" \
        || die "Cannot derive a traffic class from ${ip} (its last octet must be 2-254)"

    # A limit above the link's real capacity is not a limit. The ceiling is read
    # from the interfaces rather than assumed, so a 100 Mbps link cannot be told
    # to deliver 300 Mbps and a gigabit link is not quietly capped at a Fast
    # Ethernet figure.
    local ceiling line
    ceiling="$(link_ceiling_mbps)"
    line="$(link_line_mbps)"
    if (( mbps > ceiling )); then
        warn "${mbps} Mbps exceeds this link's usable ceiling of ${ceiling} Mbps; using ${ceiling}."
        mbps="${ceiling}"
    fi

    local wire
    wire="$(wire_mbit "${mbps}")"

    local down="" up=""
    case "${direction}" in
        both)     down="${mbps}"; up="${mbps}" ;;
        download) down="${mbps}" ;;
        upload)   up="${mbps}" ;;
    esac

    # Both directions are torn down first, so changing the direction of a
    # limit leaves no class from the previous setting behind.
    remove_shaper "${LAN_IFACE}" "${minor}"
    remove_shaper "${WAN_IFACE}" "${minor}"

    if [[ -n "${down}" ]]; then
        ensure_htb_root "${LAN_IFACE}" "${line}" || die "cannot install the LAN queue discipline"
        apply_shaper "${LAN_IFACE}" "${minor}" "${wire}" || die "cannot shape download for ${ip}"
    fi
    if [[ -n "${up}" ]]; then
        ensure_htb_root "${WAN_IFACE}" "${line}" || die "cannot install the WAN queue discipline"
        apply_shaper "${WAN_IFACE}" "${minor}" "${wire}" || die "cannot shape upload for ${ip}"
    fi

    local policy
    policy="$(policy_label "${down}" "${up}")"

    # The nftables block flag is independent of a rate limit and survives it.
    local blocked="false"
    is_blocked "${ip}" && blocked="true"

    local -a fields=()
    [[ -n "${down}" ]] && fields+=("\"download_mbps\": ${down}")
    [[ -n "${up}" ]]   && fields+=("\"upload_mbps\": ${up}")
    [[ -n "${down}" ]] && fields+=("\"download_wire_mbit\": ${wire}")
    [[ -n "${up}" ]]   && fields+=("\"upload_wire_mbit\": ${wire}")
    fields+=("\"direction\": \"${direction}\"")
    fields+=("\"policy\": \"${policy}\"")
    [[ "${blocked}" == "true" ]] && fields+=("\"blocked\": true")

    local IFS=','
    state_set "${ip}" "{ ${fields[*]} }"

    rebuild_marks || true

    info "OK: ${ip} limited to ${policy} — shaped at ${wire} Mbit/s (${OVERHEAD_PERCENT}% framing allowance)."
    if [[ -n "${up}" ]]; then
        info "    Upload is classified by packet mark $(mark_for_minor "${minor}") on ${WAN_IFACE}."
    fi
}

cmd_unlimit() {
    local ip="${1:-}"
    if [[ -z "${ip}" ]]; then
        echo "ERROR: Usage: $0 unlimit <ip>" >&2
        exit 1
    fi

    local minor
    if minor="$(class_minor_for_ip "${ip}")"; then
        remove_shaper "${LAN_IFACE}" "${minor}"
        remove_shaper "${WAN_IFACE}" "${minor}"
    else
        warn "${ip} cannot be mapped to a traffic class; clearing its record only"
    fi

    # A block is a separate decision from a rate limit and outlives it.
    if is_blocked "${ip}"; then
        state_set "${ip}" '{ "blocked": true }'
    else
        state_set "${ip}" '{}'
    fi

    rebuild_marks || true
    info "OK: bandwidth limit for ${ip} removed (uncapped)."
}

cmd_block() {
    local ip="${1:-}"
    if [[ -z "${ip}" ]]; then
        echo "ERROR: Usage: $0 block <ip>" >&2
        exit 1
    fi

    # Delete any existing drop rule first to prevent duplicates
    local handles
    handles=$(nft -a list table inet "${FW_TABLE}" 2>/dev/null | grep -E "ip (saddr|daddr) ${ip} drop" | awk '{print $NF}' || true)
    for h in ${handles}; do
        nft delete rule inet "${FW_TABLE}" forward handle "${h}" 2>/dev/null || true
    done

    # Insert drop rules in the forward chain. This is THN's firewall table, and
    # a THN firewall apply flushes it -- so a re-apply drops these rules and the
    # client becomes reachable again. `sync` re-asserts them; see the note in
    # cmd_sync.
    nft insert rule inet "${FW_TABLE}" forward ip saddr "${ip}" drop comment "thn-ui-block-${ip}" \
        || warn "could not insert the drop rule for ${ip}"
    nft insert rule inet "${FW_TABLE}" forward ip daddr "${ip}" drop comment "thn-ui-block-${ip}" \
        || warn "could not insert the return drop rule for ${ip}"

    state_merge "${ip}" '{ "blocked": true }'
    info "OK: client ${ip} blocked from the internet."
}

cmd_unblock() {
    local ip="${1:-}"
    if [[ -z "${ip}" ]]; then
        echo "ERROR: Usage: $0 unblock <ip>" >&2
        exit 1
    fi

    local handles
    handles=$(nft -a list table inet "${FW_TABLE}" 2>/dev/null | grep -E "ip (saddr|daddr) ${ip} drop|thn-ui-block-${ip}" | awk '{print $NF}' || true)
    for h in ${handles}; do
        nft delete rule inet "${FW_TABLE}" forward handle "${h}" 2>/dev/null || true
    done

    # Unblocking clears only the block flag. A rate limit recorded against the
    # same client is a separate decision and must survive, so the whole record
    # is not thrown away -- it is emptied only when the block was all it held.
    state_merge "${ip}" '{ "blocked": false }'
    python3 - "${STATE_FILE}" <<'PY'
import json, os, sys, tempfile
path = sys.argv[1]
try:
    with open(path) as f:
        data = json.load(f)
except Exception:
    data = {}
for ip in list(data):
    rec = data[ip]
    if isinstance(rec, dict) and not rec.get("blocked") and len(rec) <= 1:
        del data[ip]
d = os.path.dirname(path) or "."
fd, tmp = tempfile.mkstemp(dir=d)
with os.fdopen(fd, "w") as f:
    json.dump(data, f, indent=2, sort_keys=True)
os.replace(tmp, path)
PY
    info "OK: client ${ip} unblocked."
}

dump_live() {
    local iface
    for iface in "${LAN_IFACE}" "${WAN_IFACE}"; do
        printf '\n== %s (link speed %s Mb/s) ==\n' "${iface}" "$(iface_speed_mbps "${iface}")"
        tc -s qdisc show dev "${iface}" 2>&1 || true
        printf -- '-- classes --\n'
        tc -s class show dev "${iface}" 2>&1 || true
        printf -- '-- filters --\n'
        tc filter show dev "${iface}" 2>&1 || true
    done
    printf '\n== nft %s %s (upload classification marks) ==\n' "${NFT_FAMILY}" "${NFT_TABLE}"
    nft list table "${NFT_FAMILY}" "${NFT_TABLE}" 2>&1 || true
}

cmd_status() {
    ensure_state
    printf 'State file:      %s\n' "${STATE_FILE}"
    printf 'Link ceiling:    %s Mbps\n' "$(link_ceiling_mbps)"
    printf 'Framing allow.:  %s%%\n' "${OVERHEAD_PERCENT}"
    printf '\n'
    cat "${STATE_FILE}"
    printf '\n'
    if [[ "${DEBUG}" == "1" || "${DEBUG}" == "true" ]]; then
        dump_live
    fi
}

cmd_debug() {
    printf 'thn-client-control diagnostics\n'
    printf '  lan=%s  wan=%s  prefix=%s\n' "${LAN_IFACE}" "${WAN_IFACE}" "${LAN_PREFIX}"
    printf '  overhead=%s%%  link ceiling=%s Mbps\n' "${OVERHEAD_PERCENT}" "$(link_ceiling_mbps)"
    printf '  state=%s\n  log=%s\n' "${STATE_FILE}" "${LOG_FILE}"
    printf '  root qdiscs before THN touched them:\n'
    cat "${QDISC_BACKUP}" 2>/dev/null || true
    printf '\n-- interfaces --\n'
    ip -br addr 2>&1 || true
    printf '\n-- link speeds --\n'
    for i in "${LAN_IFACE}" "${WAN_IFACE}"; do
        printf '  %-18s %s Mb/s\n' "${i}" "$(iface_speed_mbps "${i}")"
    done
    printf '\n-- thn enablement --\n'
    printf '  forwarding: %s\n' "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unknown)"
    printf '\n-- kernel modules --\n'
    lsmod 2>/dev/null | grep -E '^(sch_htb|sch_cake|cls_fw|sch_fq_codel|sch_ingress)\b' || true
    dump_live
    printf '\n-- neighbours on %s --\n' "${LAN_IFACE}"
    ip neigh show dev "${LAN_IFACE}" 2>&1 || true
}

# cmd_sync re-applies every recorded limit.
#
# Traffic control is kernel state and does not survive a reboot, and the host's
# own restore service re-installs its CAKE discipline on the WAN at boot. This
# command is what puts THN's limits back afterwards, which is why it is meant to
# be run from a unit ordered after thn-gateway-restore.service.
cmd_sync() {
    ensure_state
    local applied=0 ip down up

    while IFS=$'\t' read -r ip down up; do
        [[ -z "${ip}" ]] && continue
        [[ -z "${down}" && -z "${up}" ]] && continue

        local minor line wire
        minor="$(class_minor_for_ip "${ip}")" \
            || { warn "skipping ${ip}: no usable traffic class"; continue; }
        line="$(link_line_mbps)"
        wire="$(wire_mbit "${down:-${up}}")"

        if [[ -n "${down}" ]]; then
            ensure_htb_root "${LAN_IFACE}" "${line}" \
                || { warn "LAN queue discipline unavailable; skipping download for ${ip}"; continue; }
            apply_shaper "${LAN_IFACE}" "${minor}" "${wire}" \
                || { warn "download re-apply failed for ${ip}"; continue; }
        fi
        if [[ -n "${up}" ]]; then
            ensure_htb_root "${WAN_IFACE}" "${line}" \
                || { warn "WAN queue discipline unavailable; skipping upload for ${ip}"; continue; }
            apply_shaper "${WAN_IFACE}" "${minor}" "${wire}" \
                || { warn "upload re-apply failed for ${ip}"; continue; }
        fi
        applied=$(( applied + 1 ))
    done < <(python3 - "${STATE_FILE}" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
except Exception:
    data = {}
for ip in sorted(data):
    if ip.startswith("__"):
        continue
    rec = data[ip] or {}
    down, up = rec.get("download_mbps") or "", rec.get("upload_mbps") or ""
    if down or up:
        print(f"{ip}\t{down}\t{up}")
PY
)

    rebuild_marks || true
    info "Re-applied limits for ${applied} client(s) from ${STATE_FILE}."
}

# cmd_scan makes devices the gateway cannot otherwise see become visible.
#
# The dashboard reads the kernel neighbour table and the dnsmasq lease file. A
# device that has sent nothing since the gateway booted is in neither, and
# "absent from both" is indistinguishable on screen from "not connected". A
# sweep gives every address on the segment a reason to answer.
cmd_scan() {
    local net="${1:-${LAN_PREFIX}}"
    ensure_state

    info "Sweeping ${net} on ${LAN_IFACE} so idle devices answer and enter the neighbour table."

    if command -v arp-scan >/dev/null 2>&1; then
        arp-scan --interface="${LAN_IFACE}" --localnet --retry=2 --timeout=400 2>&1 || true
    else
        warn "arp-scan is not installed; falling back to a ping sweep. Install it with:"
        warn "  sudo apt-get install -y arp-scan"
        local hosts
        hosts="$(python3 - "${net}" <<'PY'
import ipaddress, sys
try:
    net = ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    sys.exit(1)
for h in list(net.hosts())[:1022]:
    print(h)
PY
)" || die "${net} is not a usable network"
        printf '%s\n' "${hosts}" \
            | xargs -r -P 64 -I{} ping -c1 -W1 -I "${LAN_IFACE}" {} >/dev/null 2>&1 || true
    fi

    printf '\nDevices the gateway can now see on %s:\n' "${LAN_IFACE}"
    ip neigh show dev "${LAN_IFACE}" 2>/dev/null \
        | grep -E 'REACHABLE|STALE|DELAY|PROBE' || true
    local n
    n="$(ip neigh show dev "${LAN_IFACE}" 2>/dev/null | grep -cE 'REACHABLE|STALE|DELAY|PROBE' || true)"
    info "Total: ${n:-0} neighbour entr(ies). Reload the Devices page to see them."
}

# cmd_revert removes THN's shaping and puts the host's own discipline back.
cmd_revert() {
    info "Removing THN queue disciplines and packet marks."
    try_tc qdisc del dev "${LAN_IFACE}" root
    try_tc qdisc del dev "${WAN_IFACE}" root
    try_nft delete table "${NFT_FAMILY}" "${NFT_TABLE}"
    state_clear

    if systemctl list-unit-files 2>/dev/null | grep -q '^thn-gateway-restore\.service'; then
        info "Re-running the host's own shaping service."
        systemctl restart thn-gateway-restore.service 2>&1 \
            || warn "could not restart thn-gateway-restore.service"
    fi
    info "Done. ${QDISC_BACKUP} records what was in place before THN shaped anything."
}

case "${1:-}" in
    limit)    cmd_limit "${2:-}" "${3:-}" "${4:-both}" ;;
    unlimit)  cmd_unlimit "${2:-}" ;;
    block)    cmd_block "${2:-}" ;;
    unblock)  cmd_unblock "${2:-}" ;;
    status)   cmd_status ;;
    sync)     cmd_sync ;;
    scan)     cmd_scan "${2:-}" ;;
    debug)    cmd_debug ;;
    revert)   cmd_revert ;;
    *)
        cat >&2 <<USAGE
Usage: $0 <command>

  limit <ip> <mbps> [both|upload|download]
        Cap a client's bandwidth. The direction defaults to both.
        Example: $0 limit 10.77.0.50 30 both

  unlimit <ip>   Remove a client's bandwidth cap.
  block <ip>     Cut a client off from the internet.
  unblock <ip>   Restore a blocked client.
  status         Show the recorded limits.
  sync           Re-apply every recorded limit (run at boot).
  scan [net]     Sweep the LAN so idle devices become visible.
  debug          Dump interfaces, qdiscs, filters, marks and modules.
  revert         Remove THN shaping and re-run the host's CAKE service.

Environment overrides:
  THN_LAN_IFACE  THN_WAN_IFACE  THN_LAN_PREFIX  THN_OVERHEAD_PERCENT
  THN_LINK_EFFICIENCY_PERCENT  THN_LINK_CEIL_MBPS  THN_DEBUG=1
USAGE
        exit 1
        ;;
esac

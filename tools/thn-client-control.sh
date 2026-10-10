#!/usr/bin/env bash
# thn-client-control: Live Bandwidth Limiting and Client Control Engine
# Manages HTB classes on the LAN interface and nftables blocking rules.
set -euo pipefail

LAN_IFACE="enx00e099001812"
STATE_DIR="/var/lib/thn"
STATE_FILE="${STATE_DIR}/client_controls.json"

mkdir -p "${STATE_DIR}"
if [[ ! -f "${STATE_FILE}" ]]; then
    echo "{}" > "${STATE_FILE}"
fi

# Ensure base HTB qdisc exists on LAN interface
ensure_htb_root() {
    if ! tc qdisc show dev "${LAN_IFACE}" | grep -q "qdisc htb 1:"; then
        # Default class 99 is unconstrained full line rate (95 Mbit payload)
        tc qdisc replace dev "${LAN_IFACE}" root handle 1: htb default 99
        tc class replace dev "${LAN_IFACE}" parent 1: classid 1:1 htb rate 95mbit ceil 95mbit
        tc class replace dev "${LAN_IFACE}" parent 1:1 classid 1:99 htb rate 95mbit ceil 95mbit
        tc qdisc replace dev "${LAN_IFACE}" parent 1:99 handle 99: fq_codel
    fi
}

# Derive a unique integer classid from the last octet of the IPv4 address
get_class_id() {
    local ip="$1"
    local last_octet
    last_octet=$(echo "${ip}" | awk -F. '{print $4}')
    if [[ -z "${last_octet}" ]] || ! [[ "${last_octet}" =~ ^[0-9]+$ ]]; then
        echo "90"
    else
        echo "${last_octet}"
    fi
}

cmd_limit() {
    local ip="${1:-}"
    local rate_mbps="${2:-}"

    if [[ -z "${ip}" || -z "${rate_mbps}" ]]; then
        echo "ERROR: Usage: $0 limit <ip> <mbps>" >&2
        exit 1
    fi

    local class_id
    class_id=$(get_class_id "${ip}")

    ensure_htb_root

    # Add or replace rate-limited HTB class with FQ-CoDel leaf
    tc class replace dev "${LAN_IFACE}" parent 1:1 classid "1:${class_id}" htb rate "${rate_mbps}mbit" ceil "${rate_mbps}mbit"
    tc qdisc replace dev "${LAN_IFACE}" parent "1:${class_id}" handle "${class_id}:" fq_codel

    # Add or replace filter directing traffic for this IP to its class
    tc filter del dev "${LAN_IFACE}" protocol ip parent 1:0 prio 1 u32 match ip dst "${ip}/32" 2>/dev/null || true
    tc filter add dev "${LAN_IFACE}" protocol ip parent 1:0 prio 1 u32 match ip dst "${ip}/32" flowid "1:${class_id}"

    # Update state JSON
    python3 -c "
import json
data = {}
try:
    with open('${STATE_FILE}', 'r') as f:
        data = json.load(f)
except Exception:
    pass
if '${ip}' not in data:
    data['${ip}'] = {}
data['${ip}']['download_mbps'] = int('${rate_mbps}')
data['${ip}']['policy'] = '${rate_mbps} Mbps'
with open('${STATE_FILE}', 'w') as f:
    json.dump(data, f, indent=2)
"
    echo "SUCCESS: Bandwidth limit for ${ip} set to ${rate_mbps} Mbps"
}

cmd_unlimit() {
    local ip="${1:-}"
    if [[ -z "${ip}" ]]; then
        echo "ERROR: Usage: $0 unlimit <ip>" >&2
        exit 1
    fi

    local class_id
    class_id=$(get_class_id "${ip}")

    # Remove filter and class
    tc filter del dev "${LAN_IFACE}" protocol ip parent 1:0 prio 1 u32 match ip dst "${ip}/32" 2>/dev/null || true
    tc class del dev "${LAN_IFACE}" classid "1:${class_id}" 2>/dev/null || true

    # Update state JSON
    python3 -c "
import json
data = {}
try:
    with open('${STATE_FILE}', 'r') as f:
        data = json.load(f)
except Exception:
    pass
if '${ip}' in data:
    data['${ip}'].pop('download_mbps', None)
    data['${ip}'].pop('policy', None)
    if not data['${ip}']:
        del data['${ip}']
with open('${STATE_FILE}', 'w') as f:
    json.dump(data, f, indent=2)
"
    echo "SUCCESS: Bandwidth limit for ${ip} removed (uncapped)"
}

cmd_block() {
    local ip="${1:-}"
    if [[ -z "${ip}" ]]; then
        echo "ERROR: Usage: $0 block <ip>" >&2
        exit 1
    fi

    # Delete any existing drop rule first to prevent duplicates
    local handles
    handles=$(nft -a list table inet thn 2>/dev/null | grep -E "ip (saddr|daddr) ${ip} drop" | awk '{print $NF}' || true)
    for h in ${handles}; do
        nft delete rule inet thn forward handle "${h}" 2>/dev/null || true
    done

    # Insert drop rules in forward chain
    nft insert rule inet thn forward ip saddr "${ip}" drop comment "thn-ui-block-${ip}"
    nft insert rule inet thn forward ip daddr "${ip}" drop comment "thn-ui-block-${ip}"

    # Update state JSON
    python3 -c "
import json
data = {}
try:
    with open('${STATE_FILE}', 'r') as f:
        data = json.load(f)
except Exception:
    pass
if '${ip}' not in data:
    data['${ip}'] = {}
data['${ip}']['blocked'] = True
with open('${STATE_FILE}', 'w') as f:
    json.dump(data, f, indent=2)
"
    echo "SUCCESS: Client ${ip} blocked from internet"
}

cmd_unblock() {
    local ip="${1:-}"
    if [[ -z "${ip}" ]]; then
        echo "ERROR: Usage: $0 unblock <ip>" >&2
        exit 1
    fi

    local handles
    handles=$(nft -a list table inet thn 2>/dev/null | grep -E "ip (saddr|daddr) ${ip} drop|thn-ui-block-${ip}" | awk '{print $NF}' || true)
    for h in ${handles}; do
        nft delete rule inet thn forward handle "${h}" 2>/dev/null || true
    done

    # Update state JSON
    python3 -c "
import json
data = {}
try:
    with open('${STATE_FILE}', 'r') as f:
        data = json.load(f)
except Exception:
    pass
if '${ip}' in data:
    data['${ip}']['blocked'] = False
with open('${STATE_FILE}', 'w') as f:
    json.dump(data, f, indent=2)
"
    echo "SUCCESS: Client ${ip} unblocked"
}

cmd_status() {
    cat "${STATE_FILE}"
}

case "${1:-}" in
    limit)
        cmd_limit "${2:-}" "${3:-}"
        ;;
    unlimit)
        cmd_unlimit "${2:-}"
        ;;
    block)
        cmd_block "${2:-}"
        ;;
    unblock)
        cmd_unblock "${2:-}"
        ;;
    status)
        cmd_status
        ;;
    *)
        echo "Usage: $0 {limit <ip> <mbps>|unlimit <ip>|block <ip>|unblock <ip>|status}" >&2
        exit 1
        ;;
esac

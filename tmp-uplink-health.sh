#!/bin/bash
# Read-only uplink health check. Changes nothing.
#
# Why this exists: pings through this uplink have been showing steadily
# RISING latency across successive probes (41 -> 66 -> 88 ms). Rising latency
# in sequence is the signature of a queue filling, not of a slow link. This
# script separates the two causes by measuring latency while reading the byte
# counters, so "the link is slow" and "the link is congested" can be told
# apart instead of guessed at.

IF=enp0s31f6

echo "=== 1. IDLE LATENCY (10 probes, 0.2s apart) ==="
ping -c 10 -i 0.2 -W 2 1.1.1.1 2>&1 | tail -3

echo
echo "=== 2. UPLINK UTILISATION (2 second sample) ==="
rx1=$(cat /sys/class/net/$IF/statistics/rx_bytes)
tx1=$(cat /sys/class/net/$IF/statistics/tx_bytes)
sleep 2
rx2=$(cat /sys/class/net/$IF/statistics/rx_bytes)
tx2=$(cat /sys/class/net/$IF/statistics/tx_bytes)

rxbps=$(( (rx2 - rx1) / 2 ))
txbps=$(( (tx2 - tx1) / 2 ))
echo "  download : $(( rxbps / 1024 )) KB/s"
echo "  upload   : $(( txbps / 1024 )) KB/s"

# 100 Mbps is the negotiated line rate. Anything meaningfully below it is
# background noise; close to it means the pipe is full.
if [ $txbps -gt 10000000 ] || [ $rxbps -gt 10000000 ]; then
  echo "  VERDICT: uplink is saturated. Rising ping latency is expected."
else
  echo "  VERDICT: uplink is mostly idle. Rising latency is NOT congestion."
fi

echo
echo "=== 3. WHERE IS THE LATENCY? (per hop) ==="
trace -n -q -w 1 -m 6 1.1.1.1 2>/dev/null | tail -8 || \
  ping -c 3 192.168.1.1 | tail -2

echo
echo "=== 4. LINK PHYSICAL STATE ==="
echo "  speed   : $(cat /sys/class/net/$IF/speed) Mbps"
echo "  duplex  : $(cat /sys/class/net/$IF/duplex)"
echo "  carrier : $(cat /sys/class/net/$IF/carrier)"

echo
echo "=== 5. QUEUE DISCIPLINE ON THE UPLINK ==="
tc -s qdisc show dev $IF 2>/dev/null | head -6 || echo "  (needs root for full detail)"

echo
echo "=== 6. IS ANYTHING ELSE USING THIS HOST? ==="
ss -unp 2>/dev/null | grep -E ':(80|443|1717)' | head -5

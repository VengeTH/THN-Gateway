# Builds a THN configuration and validates it, so that the validation-coverage
# audit can be demonstrated against the real binary rather than only in tests.
#
# Verification only. `thn validate` is TierPure; nothing here applies a
# configuration, binds a socket or touches an interface.
#
# The point of this fixture is that it is COMPLETE: WAN identified, LAN
# identified and carrying the gateway address, NAT and forwarding scoped to
# real interfaces, DHCP and DNS pools inside the LAN. It exists to prove the
# widened gate is not simply always-red — a gate that rejects every document
# is as useless as one that accepts every document.

param(
    [string]$Thn = "$env:TEMP\thn-dhcp\thn.exe",
    [string]$Out = "$env:TEMP\thn-dhcp\complete.yaml",
    [switch]$Json
)

$body = @"
schema_version: 1

gateway:
  name: thn-complete
  generation: 1

network:
  wan: enp0s31f6
  lan: enp1s0
  lan_prefix: 192.168.1.1/24
  dns:
    - 1.1.1.1
    - 9.9.9.9
  mtu: 1500
  upstream_gateway: ""

nat:
  enabled: true
  # The NAT interface list is the LAN only. validation.Static refuses to
  # masquerade traffic originating on the WAN, because that is a routing loop.
  interfaces:
    - enp1s0

firewall:
  enabled: true
  backend: nftables
  default_inbound_policy: drop

qos:
  enabled: false
  algorithm: cake
  interface: ""
  download_kbps: 0
  upload_kbps: 0
  overhead_percent: 0

paths:
  config: /etc/thn/config.yaml
  state_dir: /var/lib/thn
  state_db: /var/lib/thn/state.db
  socket: /run/thn/thnd.sock
  run_dir: /run/thn
  log_file: ""

dhcp:
  enabled: true
  authoritative: true
  lease_time: 12h
  lease_max: 0
  domain: lan.home
  ranges:
    - start: 192.168.1.100
      end: 192.168.1.250
  reservations: []

dns:
  enabled: true
  local_domain: lan.home
  upstream:
    - 1.1.1.1
    - 9.9.9.9
  local_records:
    - hostname: nas
      address: 192.168.1.10

services:
  dnsmasq:
    config_file: /etc/thn/dnsmasq.conf
    lease_file: /var/lib/thn/dnsmasq.leases
"@

Set-Content -Path $Out -Value $body -Encoding UTF8

if ($Json) {
    & $Thn validate --json $Out 2>&1 | Out-String
}
else {
    & $Thn validate $Out 2>&1 | Out-String
}

Write-Output ("EXIT=" + $LASTEXITCODE)
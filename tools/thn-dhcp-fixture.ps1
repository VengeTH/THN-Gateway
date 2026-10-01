param(
    [Parameter(Mandatory = $true)][string]$Lan,
    [Parameter(Mandatory = $true)][string]$Start,
    [Parameter(Mandatory = $true)][string]$End,
    [string]$Out
)

# Writes a THN configuration whose only interesting content is the DHCP pool.
# Everything else is left at the shape configs/gateway.yaml uses so that the
# only variable between runs is the range arithmetic under test.

if (-not $Out) { $Out = Join-Path $env:TEMP "thn-dhcp-cfg.yaml" }

$body = @"
schema_version: 1

gateway:
  name: thn-gateway
  generation: 1

network:
  wan: enp0s31f6
  lan: ""
  lan_prefix: $Lan
  dns:
    - 1.1.1.1
  mtu: 1500
  upstream_gateway: ""

nat:
  enabled: true
  interfaces: []

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
  domain: lan
  ranges:
    - start: $Start
      end: $End
  reservations: []

dns:
  enabled: true
  upstream: []
  local_records: []

services:
  dnsmasq:
    config_file: $env:TEMP\thn-dhcp\dnsmasq.conf
    lease_file: $env:TEMP\thn-dhcp\dnsmasq.leases
"@

Set-Content -Path $Out -Value $body -Encoding UTF8
Write-Output $Out

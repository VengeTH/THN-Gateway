# Runs the real thn binary against a set of DHCP pool configurations and
# reports the exit status and DHCP findings for each.
#
# This is verification, not activation: nothing here applies a configuration,
# touches an interface or starts a server. Every case is a static document
# handed to `thn dhcp validate`, which is a TierPure command.

param(
    [string]$Thn = "$env:TEMP\thn-dhcp\thn.exe",
    [string]$Cfg = "$env:TEMP\thn-dhcp\cfg.yaml",
    [string]$Fixture = ".\tools\thn-dhcp-fixture.ps1"
)

$cases = @(
    @{ n = 'valid /24 interior';      lan = '192.168.1.1/24'; s = '192.168.1.10';  e = '192.168.1.200' }
    @{ n = 'reversed';                lan = '192.168.1.1/24'; s = '192.168.1.200'; e = '192.168.1.10' }
    @{ n = 'outside LAN';             lan = '192.168.1.1/24'; s = '192.168.2.10';  e = '192.168.2.100' }
    @{ n = 'start inside, end outside'; lan = '192.168.1.1/24'; s = '192.168.1.10'; e = '192.168.2.10' }
    @{ n = 'cross-subnet forward';    lan = '192.168.1.1/24'; s = '192.168.1.250'; e = '192.168.2.10' }
    @{ n = 'boundary whole subnet';   lan = '192.168.1.1/24'; s = '192.168.1.0';   e = '192.168.1.255' }
    @{ n = 'network address only';    lan = '192.168.1.1/24'; s = '192.168.1.0';   e = '192.168.1.0' }
    @{ n = 'broadcast address only';  lan = '192.168.1.1/24'; s = '192.168.1.255'; e = '192.168.1.255' }
    @{ n = 'equal endpoints';         lan = '192.168.1.1/24'; s = '192.168.1.50';  e = '192.168.1.50' }
    @{ n = 'valid /30';               lan = '192.168.1.253/30'; s = '192.168.1.253'; e = '192.168.1.254' }
    @{ n = '/30 excl gateway';        lan = '192.168.1.252/30'; s = '192.168.1.253'; e = '192.168.1.254' }
    @{ n = '/30 on the network';      lan = '192.168.1.252/30'; s = '192.168.1.252'; e = '192.168.1.252' }
    @{ n = '/30 on the broadcast';    lan = '192.168.1.252/30'; s = '192.168.1.255'; e = '192.168.1.255' }
    @{ n = 'valid /31 whole';         lan = '192.168.1.0/31'; s = '192.168.1.0';   e = '192.168.1.1' }
    @{ n = '/31 excl gateway';        lan = '192.168.1.0/31'; s = '192.168.1.1';   e = '192.168.1.1' }
    @{ n = 'valid /32';               lan = '192.168.1.1/32'; s = '192.168.1.1';   e = '192.168.1.1' }
    @{ n = '/32 pool outside';        lan = '192.168.1.1/32'; s = '192.168.1.2';   e = '192.168.1.2' }
    @{ n = '/29 excl gateway';        lan = '192.168.1.248/29'; s = '192.168.1.249'; e = '192.168.1.254' }
    @{ n = '/29 whole subnet';        lan = '192.168.1.248/29'; s = '192.168.1.248'; e = '192.168.1.255' }
    @{ n = 'space extremes min';      lan = '0.0.0.0/0'; s = '0.0.0.0';            e = '0.0.0.1' }
    @{ n = 'space extremes max';      lan = '0.0.0.0/0'; s = '255.255.255.254';    e = '255.255.255.255' }
    @{ n = 'reversed across space';   lan = '0.0.0.0/0'; s = '255.255.255.255';    e = '0.0.0.0' }
    @{ n = '/8 upper bound';          lan = '10.0.0.1/8'; s = '10.255.255.254';     e = '10.255.255.255' }
    @{ n = '/8 escapes';              lan = '10.0.0.1/8'; s = '10.255.255.254';     e = '11.0.0.1' }
)

$rows = @()

foreach ($c in $cases) {
    & $Fixture -Lan $c.lan -Start $c.s -End $c.e -Out $Cfg | Out-Null

    $out = & $Thn dhcp validate $Cfg 2>&1 | Out-String
    $code = $LASTEXITCODE

    $verdict = 'PASS'
    $detail = '-'
    if ($out -match 'Result:\s+(\w+)') { $verdict = $Matches[1] }
    if ($out -match 'error\s+(\S+)\s+(.*?)(\r?\n)') { $detail = "$($Matches[1])" }

    $pool = '-'
    if ($out -match '(\d+) pool\(s\) of (\d+) address') { $pool = "$($Matches[2]) addr" }

    $rows += [pscustomobject]@{
        Case    = $c.n
        LAN     = $c.lan
        Pool    = "$($c.s) - $($c.e)"
        Verdict = $verdict
        Size    = $pool
        Exit    = $code
        Error   = $detail
    }
}

$rows | Format-Table -AutoSize | Out-String -Width 200

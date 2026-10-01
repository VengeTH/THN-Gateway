# Runs both validation paths over one DHCP pool configuration and reports the
# verdict and exit status of each.
#
# Verification only. Nothing here applies a configuration, binds a socket or
# touches an interface: `thn validate` and `thn dhcp validate` are both
# TierPure, and no apply path exists in this build.
#
# The point of running both is that they must agree. They derive the DHCP
# policy the same way and call the same internal/dhcp validator, so a
# disagreement here means one of them stopped calling it.

param(
    [string]$Thn = "$env:TEMP\thn-dhcp\thn.exe",
    [string]$Cfg = "$env:TEMP\thn-dhcp\cfg.yaml",
    [string]$Fixture = ".\tools\thn-dhcp-fixture.ps1"
)

$cases = @(
    @{ n = 'valid interior';    lan = '192.168.1.1/24'; s = '192.168.1.10';   e = '192.168.1.200' }
    @{ n = 'reversed';          lan = '192.168.1.1/24'; s = '192.168.1.200';  e = '192.168.1.10' }
    @{ n = 'outside LAN';       lan = '192.168.1.1/24'; s = '192.168.2.10';   e = '192.168.2.100' }
    @{ n = 'cross-subnet';      lan = '192.168.1.1/24'; s = '192.168.1.250';  e = '192.168.2.10' }
    @{ n = 'network address';   lan = '192.168.1.1/24'; s = '192.168.1.0';    e = '192.168.1.0' }
    @{ n = 'broadcast address'; lan = '192.168.1.1/24'; s = '192.168.1.255';  e = '192.168.1.255' }
    @{ n = 'whole subnet';      lan = '192.168.1.1/24'; s = '192.168.1.0';    e = '192.168.1.255' }
)

function Invoke-Verdict {
    param([string[]]$CliArgs, [string]$Needle)

    $out = & $Thn @CliArgs 2>&1 | Out-String
    $code = $LASTEXITCODE

    $detail = '-'
    if ($Needle -ne '' -and $out -match [regex]::Escape($Needle)) {
        $detail = $Needle
    }
    elseif ($out -match 'error\s+(\S+)') {
        $detail = $Matches[1]
    }
    elseif ($out -match 'thn \S+: (.+)') {
        $detail = 'USAGE: ' + $Matches[1]
    }

    [pscustomobject]@{
        Verdict = if ($code -eq 0) { 'PASS' } else { 'FAIL' }
        Exit    = $code
        Field   = $detail
    }
}

$rows = @()

foreach ($c in $cases) {
    & $Fixture -Lan $c.lan -Start $c.s -End $c.e -Out $Cfg | Out-Null

    $top = Invoke-Verdict -CliArgs @('validate', $Cfg) -Needle 'dhcp.ranges'
    $svc = Invoke-Verdict -CliArgs @('dhcp', 'validate', $Cfg) -Needle 'ranges'

    $agree = if (($top.Exit -eq 0) -eq ($svc.Exit -eq 0)) { 'yes' } else { 'NO' }

    $rows += [pscustomobject]@{
        Case     = $c.n
        Pool     = "$($c.s) - $($c.e)"
        TopLevel = "$($top.Verdict)/$($top.Exit)"
        TopField = $top.Field
        Service  = "$($svc.Verdict)/$($svc.Exit)"
        SvcField = $svc.Field
        Agree    = $agree
    }
}

$rows | Format-Table -AutoSize | Out-String -Width 220

# JSON: the machine-readable path must carry the finding, not just the exit
# code, or a CI consumer sees a red build with no explanation.
Write-Output "=== thn validate --json (cross-subnet) ==="
& $Fixture -Lan '192.168.1.1/24' -Start '192.168.1.250' -End '192.168.2.10' -Out $Cfg | Out-Null
$json = & $Thn validate --json $Cfg 2>&1 | Out-String
Write-Output ("  exit " + $LASTEXITCODE)

try {
    $doc = $json | ConvertFrom-Json
    Write-Output ("  valid = " + $doc.valid)
    Write-Output ("  layers = " + ($doc.layers -join ', '))
    foreach ($f in $doc.findings) {
        Write-Output ("  [{0}] {1} :: {2}" -f $f.severity, $f.field, $f.message)
    }
    Write-Output "  (parsed as valid JSON)"
}
catch {
    Write-Output ("  INVALID JSON: " + $_.Exception.Message)
}

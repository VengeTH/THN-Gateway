# Runs the top-level `thn validate` against two DHCP pools and reports the
# verdict, exit status and the structured JSON findings.
#
# Verification only: nothing here applies a configuration.

param(
    [string]$Thn = "$env:TEMP\thn-dhcp\thn.exe",
    [string]$Cfg = "$env:TEMP\thn-dhcp\cfg.yaml",
    [string]$Fixture = ".\tools\thn-dhcp-fixture.ps1"
)

function Show-Case {
    param([string]$Label, [string]$Lan, [string]$Start, [string]$End, [switch]$Json)

    & $Fixture -Lan $Lan -Start $Start -End $End -Out $Cfg | Out-Null

    Write-Output "===== $Label ====="
    Write-Output "  LAN  $Lan"
    Write-Output "  DHCP $Start - $End"

    if ($Json) {
        $out = & $Thn dhcp validate --json $Cfg 2>&1 | Out-String
        Write-Output ("  exit " + $LASTEXITCODE)
        # Show just the DHCP findings so the structure is visible.
        ($out -split "`n") | Where-Object { $_ -match 'ranges\[0\]' } |
            ForEach-Object { Write-Output ("  " + $_.Trim()) }
    }
    else {
        $out = & $Thn validate $Cfg 2>&1 | Out-String
        Write-Output ("  exit " + $LASTEXITCODE)
        ($out -split "`n") |
            Where-Object { $_ -match 'Result:|error\s' } |
            Select-Object -First 4 |
            ForEach-Object { Write-Output ("  " + $_.Trim()) }
    }
    Write-Output ""
}

Show-Case -Label 'thn validate - valid interior pool' -Lan '192.168.1.1/24' -Start '192.168.1.10' -End '192.168.1.200'
Show-Case -Label 'thn validate - cross-subnet pool'   -Lan '192.168.1.1/24' -Start '192.168.1.250' -End '192.168.2.10'
Show-Case -Label 'thn validate - reversed pool'       -Lan '192.168.1.1/24' -Start '192.168.1.200' -End '192.168.1.10'
Show-Case -Label 'thn dhcp validate --json - cross-subnet' -Lan '192.168.1.1/24' -Start '192.168.1.250' -End '192.168.2.10' -Json

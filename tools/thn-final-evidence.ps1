# Captures the evidence the pre-applier milestone reports on, from the real
# binary. Read-only: `thn validate` and `thn readiness` are TierPure and this
# applies nothing.

param([string]$Thn = "$env:TEMP\thn-dhcp\thn.exe")

$cfg = Join-Path (Split-Path -Parent $PSScriptRoot) 'configs\gateway.yaml'

Write-Output "=== A. thn validate configs/gateway.yaml ==="
$out = & $Thn validate $cfg 2>&1 | Out-String
Write-Output ("  exit " + $LASTEXITCODE)
($out -split "`n") | Where-Object { $_ -match 'Result:|warning |error |info ' } |
    ForEach-Object { Write-Output ("  " + $_.Trim()) }

Write-Output ""
Write-Output "=== A. thn validate --json ==="
$json = & $Thn validate --json $cfg 2>&1 | Out-String
Write-Output ("  exit " + $LASTEXITCODE)
try {
    $d = $json | ConvertFrom-Json
    $errs = @($d.findings | Where-Object { $_.severity -eq 'error' })
    Write-Output ("  valid    = " + $d.valid)
    Write-Output ("  layers   = " + ($d.layers -join ', '))
    Write-Output ("  findings = " + @($d.findings).Count + " (" + $errs.Count + " error)")
    Write-Output "  (parsed as valid JSON)"
}
catch { Write-Output ("  INVALID JSON: " + $_.Exception.Message) }

Write-Output ""
Write-Output "=== C. thn readiness ==="
$out = & $Thn readiness $cfg 2>&1 | Out-String
Write-Output ("  exit " + $LASTEXITCODE)
($out -split "`n") | Where-Object { $_ -match 'Verdict:|Can apply:|BLOCK|^  - |untouched|blocked by the BUILD' } |
    ForEach-Object { Write-Output ("  " + $_.TrimEnd()) }

Write-Output ""
Write-Output "=== F. safety invariants ==="
$canApply = (Select-String -Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'internal\activation\activation.go') `
        -Pattern 'func CanApply\(\) bool \{ return (\w+) \}').Matches[0].Groups[1].Value
Write-Output ("  activation.CanApply() source = " + $canApply)
$out = & $Thn activate --confirm-present 2>&1 | Out-String
Write-Output ("  thn activate exit = " + $LASTEXITCODE)
Write-Output ("  says untouched   = " + $out.Contains('Current network remains untouched'))
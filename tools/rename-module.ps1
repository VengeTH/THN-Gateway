#!/usr/bin/env pwsh
# Updates module path and all internal imports from old module path to new module path.
# Usage: ./tools/rename-module.ps1 -Old "github.com/venth/thn-gateway" -New "github.com/VengeTH/THN-Gateway"

param(
    [string]$Old = "github.com/venth/thn-gateway",
    [string]$New = "github.com/VengeTH/THN-Gateway"
)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$utf8NoBom = New-Object System.Text.UTF8Encoding $false

# 1. Update go.mod
if (Test-Path "go.mod") {
    $content = [System.IO.File]::ReadAllText((Resolve-Path "go.mod"), [System.Text.Encoding]::UTF8)
    if ($content.Contains($Old)) {
        $updated = $content.Replace($Old, $New)
        [System.IO.File]::WriteAllText((Resolve-Path "go.mod"), $updated, $utf8NoBom)
        Write-Host "Updated go.mod"
    }
}

# 2. Update all .go files
$count = 0
Get-ChildItem -Recurse -Filter *.go | ForEach-Object {
    $path = $_.FullName
    $content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    if ($content.Contains($Old)) {
        $updated = $content.Replace($Old, $New)
        [System.IO.File]::WriteAllText($path, $updated, $utf8NoBom)
        $count++
    }
}

Write-Host "Updated $count Go source files."

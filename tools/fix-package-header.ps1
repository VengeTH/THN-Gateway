#!/usr/bin/env pwsh
# Removes a duplicated leading `package <name>` line from Go source files.
#
# The file writer occasionally emits the package clause twice when a file
# begins with a long doc comment, producing:
#     package foo
#     // Package foo does ...
#     package foo
# which fails to parse with "imports must appear before other declarations".
#
# Usage:  ./tools/fix-package-header.ps1 [-WhatIf]
param([switch]$WhatIf)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

$pkgLine = '^package\s+[a-zA-Z0-9_]+$'
$fixed = @()

Get-ChildItem -Recurse -Filter *.go | ForEach-Object {
    $path = $_.FullName
    $lines = [System.IO.File]::ReadAllLines($path)

    # Find every index that is exactly a package clause.
    $idx = @()
    for ($i = 0; $i -lt $lines.Length; $i++) {
        if ($lines[$i] -match $pkgLine) { $idx += $i }
    }

    # The bug is specifically: package clause at line 0, then more content,
    # then a second package clause. Drop everything before the last one.
    if ($idx.Count -ge 2 -and $idx[0] -eq 0) {
        $keep = $idx[-1]
        $new = $lines[$keep..($lines.Length - 1)]
        if ($WhatIf) {
            Write-Host "WOULD FIX: $path (dropping $($keep) leading line(s))"
        } else {
            [System.IO.File]::WriteAllLines($path, $new)
            $fixed += $path
            Write-Host "FIXED: $path (dropped $keep leading line(s))"
        }
    }
}

if (-not $WhatIf -and $fixed.Count -gt 0) {
    Write-Host ""
    Write-Host "Repaired $($fixed.Count) file(s). Run 'gofmt -w .' next."
} elseif ($fixed.Count -eq 0) {
    Write-Host "No duplicated package headers found."
}

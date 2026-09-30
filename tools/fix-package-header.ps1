#!/usr/bin/env pwsh
# Removes a duplicated leading `package <name>` line from Go source files.
#
# The file writer occasionally emits the package clause before the doc comment
# that belongs to it, producing:
#
#     package foo
#     // Package foo does ...
#     package foo
#
# which fails to parse with "imports must appear before other declarations".
#
# Only the stray leading clause is removed. An earlier version dropped
# everything before the last clause, which also removed the package
# documentation - a silent loss that is particularly costly in this codebase,
# where the doc comment is where the design rationale lives.
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

    # The bug is a package clause at line 0 followed by more content and then
    # a second package clause. Removing line 0 alone is sufficient, and keeps
    # the doc comment that follows it.
    if ($idx.Count -ge 2 -and $idx[0] -eq 0) {
        $drop = 1
        # Also drop the blank lines the stray clause left behind, so the file
        # still starts with its documentation.
        while ($drop -lt $lines.Length -and $lines[$drop].Trim() -eq '') { $drop++ }

        $new = $lines[$drop..($lines.Length - 1)]

        if ($WhatIf) {
            Write-Host "WOULD FIX: $path (dropping $drop leading line(s))"
        } else {
            [System.IO.File]::WriteAllLines($path, $new)
            $fixed += $path
            Write-Host "FIXED: $path (dropped $drop leading line(s))"
        }
    }
}

if (-not $WhatIf -and $fixed.Count -gt 0) {
    Write-Host ""
    Write-Host "Repaired $($fixed.Count) file(s). Run 'gofmt -w .' next."
} elseif ($fixed.Count -eq 0) {
    Write-Host "No duplicated package headers found."
}

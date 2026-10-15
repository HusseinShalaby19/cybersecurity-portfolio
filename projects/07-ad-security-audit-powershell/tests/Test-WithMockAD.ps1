<#
  Offline test: runs Invoke-ADSecurityAudit.ps1 against a stub ActiveDirectory
  module containing a fictional directory with known weaknesses, then checks
  that each weakness is reported and that names are masked by default.
  Works on Windows or Linux with PowerShell 7.
#>
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:PSModulePath = (Join-Path $here 'mock') + [IO.Path]::PathSeparator + $env:PSModulePath
$out = Join-Path ([IO.Path]::GetTempPath()) "ad-audit-test-$([guid]::NewGuid())"

& (Join-Path $here '..\Invoke-ADSecurityAudit.ps1'.Replace('\', [IO.Path]::DirectorySeparatorChar)) -OutputPath $out | Out-Null

$summary = Import-Csv (Join-Path $out 'summary.csv')
$expected = @{
    'AD-01' = 2   # stale user + never-logged-on user
    'AD-02' = 2   # lab.user03, svc-lab-sql
    'AD-03' = 1
    'AD-05' = 1   # svc-lab-sql (krbtgt excluded)
    'AD-06' = 1
    'AD-07' = 1
    'AD-08' = 1   # LAB-APP01 (DC excluded)
    'AD-09' = 1
    'AD-10' = 2   # min length 8, lockout 0
    'AD-11' = 1
    'AD-12' = 1
}
$failed = 0
foreach ($id in $expected.Keys | Sort-Object) {
    $actual = [int]($summary | Where-Object Id -eq $id).Count
    $ok = $actual -eq $expected[$id]
    if (-not $ok) { $failed++ }
    '{0} {1}: expected {2}, got {3}' -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $id, $expected[$id], $actual
}
$leak = Get-ChildItem $out -File | Select-String -Pattern 'lab\.user|svc-lab-sql|lab\.admin' -SimpleMatch:$false
if ($leak) { $failed++; 'FAIL names leaked into output' } else { 'PASS account names masked in all output files' }
Remove-Item $out -Recurse -Force
if ($failed) { throw "$failed check(s) failed" } else { 'All checks passed.' }

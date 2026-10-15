<#
.SYNOPSIS
    Read-only Active Directory security audit.

.DESCRIPTION
    Collects common AD hygiene and privilege findings and writes them to CSV
    files plus a summary HTML report. The script only READS from Active
    Directory - it never modifies objects.

    Checks:
      AD-01  Enabled users inactive for more than -InactiveDays
      AD-02  Users with PasswordNeverExpires
      AD-03  Users with PasswordNotRequired
      AD-04  Members of privileged groups (recursive)
      AD-05  Kerberoastable user accounts (user objects with an SPN)
      AD-06  AS-REP roastable accounts (Kerberos pre-auth disabled)
      AD-07  Accounts storing passwords with reversible encryption
      AD-08  Non-DC computers trusted for unconstrained delegation
      AD-09  krbtgt password age
      AD-10  Default domain password and lockout policy
      AD-11  Enabled computers inactive for more than -InactiveDays
      AD-12  Built-in Administrator account usage

    Report output masks account names by default (-ShowNames to include them).
    Treat any output as confidential: do not upload reports from a real
    environment to a public repository.

.PARAMETER OutputPath
    Folder for the CSV/HTML output. Created if missing.

.PARAMETER InactiveDays
    Days without logon before an account is considered stale. Default 90.

.PARAMETER ShowNames
    Include real sAMAccountNames in the output (default: masked).

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -OutputPath .\ad-audit -InactiveDays 90

.NOTES
    Requires: RSAT ActiveDirectory module, a domain-joined machine, and an
    account with read access to the directory (a standard domain user can read
    most of these attributes).
    Status: written for a disposable lab domain; validate in your own lab
    before relying on it.
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\ad-audit-$(Get-Date -Format yyyyMMdd-HHmm)",
    [ValidateRange(1, 3650)][int]$InactiveDays = 90,
    [switch]$ShowNames
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    throw "The ActiveDirectory PowerShell module is required (install RSAT: Active Directory DS tools)."
}

$null = New-Item -ItemType Directory -Path $OutputPath -Force
$domain = Get-ADDomain
$cutoff = (Get-Date).AddDays(-$InactiveDays)
$findings = [System.Collections.Generic.List[object]]::new()
$sha = [System.Security.Cryptography.SHA256]::Create()

function Get-Label {
    param([string]$Name)
    if ($ShowNames) { return $Name }
    $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Name.ToLowerInvariant()))
    return 'acct-' + ([BitConverter]::ToString($hash) -replace '-', '').Substring(0, 8).ToLower()
}

function Add-Finding {
    param(
        [string]$Id, [string]$Severity, [string]$Title,
        [object[]]$Items, [string]$Recommendation
    )
    $count = @($Items).Count
    $findings.Add([pscustomobject]@{
        Id = $Id; Severity = $Severity; Title = $Title; Count = $count
        Recommendation = $Recommendation
    })
    if ($count -gt 0) {
        $Items | Export-Csv -Path (Join-Path $OutputPath "$Id.csv") -NoTypeInformation -Encoding UTF8
    }
    Write-Host ("[{0,-8}] {1} {2}: {3}" -f $Severity.ToUpper(), $Id, $Title, $count)
}

$userProps = 'Enabled', 'LastLogonDate', 'PasswordNeverExpires', 'PasswordNotRequired',
             'ServicePrincipalName', 'DoesNotRequirePreAuth', 'AllowReversiblePasswordEncryption',
             'PasswordLastSet', 'whenCreated', 'adminCount'
$users = Get-ADUser -Filter * -Properties $userProps

function Select-UserView {
    param([Parameter(ValueFromPipeline)]$User)
    process {
        [pscustomobject]@{
            Account         = Get-Label $User.SamAccountName
            Enabled         = $User.Enabled
            LastLogonDate   = $User.LastLogonDate
            PasswordLastSet = $User.PasswordLastSet
            AdminCount      = $User.adminCount
        }
    }
}

# AD-01 stale users (LastLogonDate is replicated lastLogonTimestamp: accurate to ~14 days)
$stale = $users | Where-Object {
    $_.Enabled -and (($null -eq $_.LastLogonDate -and $_.whenCreated -lt $cutoff) -or $_.LastLogonDate -lt $cutoff)
}
Add-Finding 'AD-01' 'medium' "Enabled users inactive > $InactiveDays days" ($stale | Select-UserView) `
    'Disable, then delete after the retention period, following the leaver process.'

# AD-02 / AD-03
Add-Finding 'AD-02' 'medium' 'Password never expires' ($users | Where-Object { $_.Enabled -and $_.PasswordNeverExpires } | Select-UserView) `
    'Remove the flag; move service accounts to gMSA where possible.'
Add-Finding 'AD-03' 'high' 'Password not required' ($users | Where-Object { $_.Enabled -and $_.PasswordNotRequired } | Select-UserView) `
    'Clear PASSWD_NOTREQD and ensure each account has a strong password.'

# AD-04 privileged group membership
$privGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
              'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins'
$privMembers = foreach ($g in $privGroups) {
    $grp = Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue
    if (-not $grp) { continue }
    Get-ADGroupMember -Identity $grp -Recursive | ForEach-Object {
        [pscustomobject]@{ Group = $g; Member = Get-Label $_.SamAccountName; ObjectClass = $_.objectClass }
    }
}
Add-Finding 'AD-04' 'info' 'Privileged group memberships (review each)' $privMembers `
    'Keep membership minimal; use separate admin accounts; Account/Backup/Server/Print Operators should normally be empty.'

# AD-05 Kerberoastable
$kerberoastable = $users | Where-Object {
    $_.Enabled -and $_.ServicePrincipalName -and $_.SamAccountName -ne 'krbtgt'
} | ForEach-Object {
    [pscustomobject]@{
        Account = Get-Label $_.SamAccountName; SPNCount = @($_.ServicePrincipalName).Count
        PasswordLastSet = $_.PasswordLastSet; Privileged = [bool]$_.adminCount
    }
}
Add-Finding 'AD-05' 'high' 'Kerberoastable user accounts (SPN set)' $kerberoastable `
    'Use gMSA, or 25+ character random passwords rotated regularly; enforce AES-only Kerberos.'

# AD-06 / AD-07
Add-Finding 'AD-06' 'high' 'Kerberos pre-authentication disabled (AS-REP roastable)' ($users | Where-Object { $_.Enabled -and $_.DoesNotRequirePreAuth } | Select-UserView) `
    'Re-enable Kerberos pre-authentication.'
Add-Finding 'AD-07' 'high' 'Reversible password encryption enabled' ($users | Where-Object { $_.Enabled -and $_.AllowReversiblePasswordEncryption } | Select-UserView) `
    'Disable reversible encryption and reset the affected passwords.'

# AD-08 unconstrained delegation on non-DCs
$dcNames = (Get-ADDomainController -Filter *).Name
$unconstrained = Get-ADComputer -Filter 'TrustedForDelegation -eq $true' -Properties TrustedForDelegation, OperatingSystem |
    Where-Object { $_.Name -notin $dcNames } |
    ForEach-Object { [pscustomobject]@{ Computer = Get-Label $_.Name; OperatingSystem = $_.OperatingSystem } }
Add-Finding 'AD-08' 'high' 'Non-DC computers with unconstrained delegation' $unconstrained `
    'Replace with constrained or resource-based constrained delegation.'

# AD-09 krbtgt
$krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
$krbAge = [int]((Get-Date) - $krbtgt.PasswordLastSet).TotalDays
$krbItems = if ($krbAge -gt 180) { @([pscustomobject]@{ PasswordAgeDays = $krbAge }) } else { @() }
Add-Finding 'AD-09' 'medium' "krbtgt password older than 180 days (age: $krbAge days)" $krbItems `
    'Rotate krbtgt twice, allowing replication between resets.'

# AD-10 password / lockout policy
$pol = Get-ADDefaultDomainPasswordPolicy
$polIssues = @()
if ($pol.MinPasswordLength -lt 12) { $polIssues += [pscustomobject]@{ Setting = 'MinPasswordLength'; Value = $pol.MinPasswordLength; Expected = '>= 12 (14+ preferred)' } }
if (-not $pol.ComplexityEnabled) { $polIssues += [pscustomobject]@{ Setting = 'ComplexityEnabled'; Value = $false; Expected = 'True, or a banned-password list' } }
if ($pol.LockoutThreshold -eq 0) { $polIssues += [pscustomobject]@{ Setting = 'LockoutThreshold'; Value = 0; Expected = '5-10 attempts' } }
if ($pol.ReversibleEncryptionEnabled) { $polIssues += [pscustomobject]@{ Setting = 'ReversibleEncryptionEnabled'; Value = $true; Expected = 'False' } }
Add-Finding 'AD-10' 'medium' 'Default domain password / lockout policy weaknesses' $polIssues `
    'Align with your password standard; add fine-grained policies for admins and service accounts.'

# AD-11 stale computers
$staleComputers = Get-ADComputer -Filter 'Enabled -eq $true' -Properties LastLogonDate, OperatingSystem |
    Where-Object { $_.LastLogonDate -lt $cutoff } |
    ForEach-Object { [pscustomobject]@{ Computer = Get-Label $_.Name; OperatingSystem = $_.OperatingSystem; LastLogonDate = $_.LastLogonDate } }
Add-Finding 'AD-11' 'low' "Enabled computers inactive > $InactiveDays days" $staleComputers `
    'Confirm decommissioning, then disable and move to a quarantine OU.'

# AD-12 built-in Administrator (RID 500) recently used
$rid500 = $users | Where-Object { $_.SID.Value -eq "$($domain.DomainSID.Value)-500" }
$rid500Items = if ($rid500 -and $rid500.Enabled -and $rid500.LastLogonDate -gt (Get-Date).AddDays(-30)) { @($rid500 | Select-UserView) } else { @() }
Add-Finding 'AD-12' 'medium' 'Built-in Administrator used in the last 30 days' $rid500Items `
    'Use named admin accounts; keep RID 500 for break-glass only, with a vaulted password.'

# Summary
$findings | Export-Csv -Path (Join-Path $OutputPath 'summary.csv') -NoTypeInformation -Encoding UTF8
$rows = ($findings | ForEach-Object {
    "<tr class='$($_.Severity)'><td>$($_.Id)</td><td>$($_.Severity)</td><td>$([Net.WebUtility]::HtmlEncode($_.Title))</td><td>$($_.Count)</td><td>$([Net.WebUtility]::HtmlEncode($_.Recommendation))</td></tr>"
}) -join "`n"
@"
<!doctype html><html><head><meta charset="utf-8"><title>AD security audit</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2em}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:6px 10px;text-align:left}
tr.high td:nth-child(2){color:#b00020;font-weight:600}tr.medium td:nth-child(2){color:#b36b00}</style></head><body>
<h1>Active Directory security audit</h1>
<p>Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm'). Inactivity threshold: $InactiveDays days. Names masked: $(-not $ShowNames).</p>
<table><tr><th>ID</th><th>Severity</th><th>Check</th><th>Count</th><th>Recommendation</th></tr>
$rows
</table><p>Detail for each non-zero check is in the matching CSV file.</p></body></html>
"@ | Set-Content -Path (Join-Path $OutputPath 'report.html') -Encoding UTF8

Write-Host "`nReport written to $((Resolve-Path $OutputPath).Path)"

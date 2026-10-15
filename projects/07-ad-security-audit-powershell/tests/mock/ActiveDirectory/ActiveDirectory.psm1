# Stub "ActiveDirectory" module for offline testing of Invoke-ADSecurityAudit.ps1.
# Returns a small fictional directory with known weaknesses. No real data.

$script:Now = Get-Date
$script:DomainSid = 'S-1-5-21-1000000000-2000000000-3000000000'

function New-MockUser($Sam, $Rid, [hashtable]$p = @{}) {
    $base = [ordered]@{
        SamAccountName = $Sam; Name = $Sam; SID = [pscustomobject]@{ Value = "$script:DomainSid-$Rid" }
        Enabled = $true; LastLogonDate = $script:Now.AddDays(-2); PasswordNeverExpires = $false
        PasswordNotRequired = $false; ServicePrincipalName = @(); DoesNotRequirePreAuth = $false
        AllowReversiblePasswordEncryption = $false; PasswordLastSet = $script:Now.AddDays(-30)
        whenCreated = $script:Now.AddDays(-400); adminCount = $null; objectClass = 'user'
    }
    foreach ($k in $p.Keys) { $base[$k] = $p[$k] }
    [pscustomobject]$base
}

$script:Users = @(
    New-MockUser 'Administrator' 500 @{ LastLogonDate = $script:Now.AddDays(-3); adminCount = 1 }
    New-MockUser 'krbtgt' 502 @{ Enabled = $false; PasswordLastSet = $script:Now.AddDays(-900); ServicePrincipalName = @('kadmin/changepw') }
    New-MockUser 'lab.user01' 1101
    New-MockUser 'lab.user02' 1102 @{ LastLogonDate = $script:Now.AddDays(-200) }                       # stale
    New-MockUser 'lab.user03' 1103 @{ PasswordNeverExpires = $true }
    New-MockUser 'lab.user04' 1104 @{ PasswordNotRequired = $true }
    New-MockUser 'svc-lab-sql' 1105 @{ ServicePrincipalName = @('MSSQLSvc/lab-sql01:1433'); PasswordNeverExpires = $true; adminCount = 1 }
    New-MockUser 'lab.user06' 1106 @{ DoesNotRequirePreAuth = $true }
    New-MockUser 'lab.user07' 1107 @{ AllowReversiblePasswordEncryption = $true }
    New-MockUser 'lab.user08' 1108 @{ LastLogonDate = $null; whenCreated = $script:Now.AddDays(-150) }  # never logged on
    New-MockUser 'lab.admin01' 1109 @{ adminCount = 1 }
)

function Get-ADDomain { [pscustomobject]@{ DNSRoot = 'lab.example'; DomainSID = [pscustomobject]@{ Value = $script:DomainSid } } }
function Get-ADUser {
    [CmdletBinding()] param([Parameter(Position = 0)]$Identity, $Filter, $Properties)
    if ($Identity) { return $script:Users | Where-Object SamAccountName -eq $Identity }
    $script:Users
}
function Get-ADGroup {
    [CmdletBinding()] param($Filter)
    if ($Filter -match "'(.+)'") { $n = $Matches[1] }
    if ($n -in 'Domain Admins', 'Administrators', 'Backup Operators') { [pscustomobject]@{ Name = $n } }
}
function Get-ADGroupMember {
    [CmdletBinding()] param($Identity, [switch]$Recursive)
    switch ($Identity.Name) {
        'Domain Admins'    { $script:Users | Where-Object SamAccountName -in 'Administrator', 'lab.admin01', 'svc-lab-sql' }
        'Administrators'   { $script:Users | Where-Object SamAccountName -in 'Administrator', 'lab.admin01' }
        'Backup Operators' { $script:Users | Where-Object SamAccountName -eq 'lab.user03' }
    }
}
function Get-ADDomainController { [CmdletBinding()] param($Filter) [pscustomobject]@{ Name = 'LAB-DC01' } }
function Get-ADComputer {
    [CmdletBinding()] param($Filter, $Properties)
    $all = @(
        [pscustomobject]@{ Name = 'LAB-DC01'; Enabled = $true; TrustedForDelegation = $true; OperatingSystem = 'Windows Server 2022'; LastLogonDate = $script:Now }
        [pscustomobject]@{ Name = 'LAB-APP01'; Enabled = $true; TrustedForDelegation = $true; OperatingSystem = 'Windows Server 2019'; LastLogonDate = $script:Now }
        [pscustomobject]@{ Name = 'LAB-WS-OLD'; Enabled = $true; TrustedForDelegation = $false; OperatingSystem = 'Windows 10'; LastLogonDate = $script:Now.AddDays(-300) }
    )
    if ($Filter -match 'TrustedForDelegation') { $all | Where-Object TrustedForDelegation } else { $all | Where-Object Enabled }
}
function Get-ADDefaultDomainPasswordPolicy {
    [pscustomobject]@{ MinPasswordLength = 8; ComplexityEnabled = $true; LockoutThreshold = 0; ReversibleEncryptionEnabled = $false }
}

Export-ModuleMember -Function Get-AD*

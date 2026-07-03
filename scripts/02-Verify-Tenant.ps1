# 02-Verify-Tenant.ps1
# IAM-006 - Enterprise Identity Operations & Risk Analytics
# Purpose:
#   Verifies that the controlled-chaos tenant and privileged risk findings were created successfully.
#
# Required Graph connection:
# Connect-MgGraph -UseDeviceCode -Scopes "User.Read.All","Group.Read.All","Application.Read.All","Directory.Read.All","RoleManagement.Read.Directory"

$ErrorActionPreference = "Stop"

Write-Host "`nIAM-006 Tenant Verification" -ForegroundColor Cyan

$Context = Get-MgContext
if (-not $Context) {
    throw "Not connected to Microsoft Graph. Run Connect-MgGraph first."
}

New-Item -ItemType Directory -Force -Path ".\exports" | Out-Null
New-Item -ItemType Directory -Force -Path ".\reports" | Out-Null

$Domain = (Get-MgDomain | Where-Object { $_.IsDefault -eq $true }).Id

Write-Host "Connected tenant: $($Context.TenantId)" -ForegroundColor Green
Write-Host "Default domain:   $Domain" -ForegroundColor Green

Write-Host "`nCollecting tenant inventory..." -ForegroundColor Cyan

$Users  = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,Department,JobTitle,UserType,PasswordPolicies
$Groups = Get-MgGroup -All -Property Id,DisplayName,SecurityEnabled
$Apps   = Get-MgApplication -All -Property Id,AppId,DisplayName,PasswordCredentials,KeyCredentials

$LabUsers = $Users | Where-Object { $_.UserPrincipalName -like "*@$Domain" -and $_.DisplayName -match "\d+$" }

$DepartmentGroups = $Groups | Where-Object {
    $_.DisplayName -in @(
        "GG-Engineering","GG-IT","GG-Security","GG-Finance",
        "GG-HR","GG-Legal","GG-Marketing","GG-Operations"
    )
}

$DisabledUsers = $Users | Where-Object { $_.AccountEnabled -eq $false }

$PasswordNeverExpires = $Users | Where-Object {
    $_.PasswordPolicies -match "DisablePasswordExpiration"
}

$OwnerlessApps = @()
foreach ($App in $Apps) {
    $Owners = Get-MgApplicationOwner -ApplicationId $App.Id -ErrorAction SilentlyContinue
    if (-not $Owners -or $Owners.Count -eq 0) {
        $OwnerlessApps += $App
    }
}

Write-Host "`nChecking wrong membership findings..." -ForegroundColor Cyan

$SecurityGroup = Get-MgGroup -Filter "displayName eq 'GG-Security'" -ErrorAction SilentlyContinue
$WrongMarketingMembers = @()

if ($SecurityGroup) {
    $SecurityMembers = Get-MgGroupMember -GroupId $SecurityGroup.Id -All -ErrorAction SilentlyContinue

    foreach ($Member in $SecurityMembers) {
        $User = Get-MgUser -UserId $Member.Id -Property DisplayName,UserPrincipalName,Department -ErrorAction SilentlyContinue
        if ($User -and $User.Department -eq "Marketing") {
            $WrongMarketingMembers += $User
        }
    }
}

Write-Host "`nChecking excessive access findings..." -ForegroundColor Cyan

$ExcessiveAccessUsers = @()
$ExpectedExcessiveUPNs = @(
    "alex.adams26@$Domain",
    "blake.baker27@$Domain",
    "cameron.chen28@$Domain",
    "casey.davis29@$Domain",
    "dakota.evans30@$Domain"
)

foreach ($UPN in $ExpectedExcessiveUPNs) {
    $User = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue
    if ($User) {
        $Memberships = Get-MgUserMemberOf -UserId $User.Id -All -ErrorAction SilentlyContinue
        if ($Memberships.Count -ge 4) {
            $ExcessiveAccessUsers += [PSCustomObject]@{
                DisplayName = $User.DisplayName
                UserPrincipalName = $User.UserPrincipalName
                MembershipCount = $Memberships.Count
            }
        }
    }
}

Write-Host "`nChecking privileged role assignments..." -ForegroundColor Cyan

$PrivilegedFindings = @()
$RolesToCheck = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Security Administrator",
    "User Administrator"
)

foreach ($RoleName in $RolesToCheck) {
    $Role = Get-MgDirectoryRole -All | Where-Object { $_.DisplayName -eq $RoleName } | Select-Object -First 1
    if ($Role) {
        $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All -ErrorAction SilentlyContinue
        foreach ($Member in $Members) {
            $User = Get-MgUser -UserId $Member.Id -Property DisplayName,UserPrincipalName,Department,AccountEnabled -ErrorAction SilentlyContinue
            if ($User) {
                $PrivilegedFindings += [PSCustomObject]@{
                    Role = $RoleName
                    DisplayName = $User.DisplayName
                    UserPrincipalName = $User.UserPrincipalName
                    Department = $User.Department
                    AccountEnabled = $User.AccountEnabled
                }
            }
        }
    }
}

$PrivilegedFindings | Export-Csv ".\exports\Privileged-Role-Assignments.csv" -NoTypeInformation
$DisabledUsers | Select DisplayName,UserPrincipalName,Department,AccountEnabled | Export-Csv ".\exports\Disabled-Users.csv" -NoTypeInformation
$PasswordNeverExpires | Select DisplayName,UserPrincipalName,Department,PasswordPolicies | Export-Csv ".\exports\Password-Never-Expires.csv" -NoTypeInformation
$OwnerlessApps | Select DisplayName,AppId,Id | Export-Csv ".\exports\Ownerless-Applications.csv" -NoTypeInformation
$WrongMarketingMembers | Select DisplayName,UserPrincipalName,Department | Export-Csv ".\exports\Wrong-Marketing-Security-Members.csv" -NoTypeInformation
$ExcessiveAccessUsers | Export-Csv ".\exports\Excessive-Access-Users.csv" -NoTypeInformation

$Summary = [PSCustomObject]@{
    TotalUsers = $Users.Count
    LabUsers = $LabUsers.Count
    DepartmentGroups = $DepartmentGroups.Count
    DisabledUsers = $DisabledUsers.Count
    PasswordNeverExpires = $PasswordNeverExpires.Count
    OwnerlessApps = $OwnerlessApps.Count
    WrongMarketingSecurityMembers = $WrongMarketingMembers.Count
    ExcessiveAccessUsers = $ExcessiveAccessUsers.Count
    PrivilegedAssignments = $PrivilegedFindings.Count
}

$Summary | Export-Csv ".\exports\Tenant-Verification-Summary.csv" -NoTypeInformation

$Report = @"
# IAM-006 Tenant Verification Report

Generated: $(Get-Date)

## Tenant Inventory

| Metric | Count |
|---|---:|
| Total Users | $($Users.Count) |
| IAM-006 Lab Users | $($LabUsers.Count) |
| Department Groups | $($DepartmentGroups.Count) |
| Disabled Users | $($DisabledUsers.Count) |
| Password Never Expires Accounts | $($PasswordNeverExpires.Count) |
| Ownerless Applications | $($OwnerlessApps.Count) |
| Wrong Marketing Users in GG-Security | $($WrongMarketingMembers.Count) |
| Excessive Access Users | $($ExcessiveAccessUsers.Count) |
| Privileged Role Assignments | $($PrivilegedFindings.Count) |

## Verification Status

| Control | Expected | Actual | Status |
|---|---:|---:|---|
| Lab users | 200 | $($LabUsers.Count) | $(if ($LabUsers.Count -ge 200) {"PASS"} else {"REVIEW"}) |
| Department groups | 8 | $($DepartmentGroups.Count) | $(if ($DepartmentGroups.Count -ge 8) {"PASS"} else {"REVIEW"}) |
| Disabled users | 5+ | $($DisabledUsers.Count) | $(if ($DisabledUsers.Count -ge 5) {"PASS"} else {"REVIEW"}) |
| Password exceptions | 10+ | $($PasswordNeverExpires.Count) | $(if ($PasswordNeverExpires.Count -ge 10) {"PASS"} else {"REVIEW"}) |
| Ownerless applications | 5+ | $($OwnerlessApps.Count) | $(if ($OwnerlessApps.Count -ge 5) {"PASS"} else {"REVIEW"}) |
| Wrong memberships | 8+ | $($WrongMarketingMembers.Count) | $(if ($WrongMarketingMembers.Count -ge 8) {"PASS"} else {"REVIEW"}) |
| Excessive access | 5+ | $($ExcessiveAccessUsers.Count) | $(if ($ExcessiveAccessUsers.Count -ge 5) {"PASS"} else {"REVIEW"}) |
| Privileged assignments | 5+ | $($PrivilegedFindings.Count) | $(if ($PrivilegedFindings.Count -ge 5) {"PASS"} else {"REVIEW"}) |

## Output Files

- exports/Tenant-Verification-Summary.csv
- exports/Privileged-Role-Assignments.csv
- exports/Disabled-Users.csv
- exports/Password-Never-Expires.csv
- exports/Ownerless-Applications.csv
- exports/Wrong-Marketing-Security-Members.csv
- exports/Excessive-Access-Users.csv

## Summary

The IAM-006 tenant now contains realistic identity operations findings across identity hygiene, access control, application governance, and privileged access. This verified dataset will be used by the dashboards and risk analytics scripts in the next phases.
"@

$Report | Set-Content ".\reports\Tenant-Verification-Report.md" -Encoding UTF8

Write-Host "`nVerification Summary" -ForegroundColor Cyan
$Summary | Format-List

Write-Host "`nTenant verification complete." -ForegroundColor Green
Write-Host "Report: .\reports\Tenant-Verification-Report.md" -ForegroundColor Green
Write-Host "Exports: .\exports" -ForegroundColor Green

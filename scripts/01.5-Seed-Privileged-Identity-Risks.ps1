# 01.5-Seed-Privileged-Identity-Risks.ps1
# IAM-006 - Enterprise Identity Operations & Risk Analytics
# Purpose:
#   Seeds intentional privileged access findings for IAM-006 dashboards.
#
# Required Graph connection:
# Connect-MgGraph -UseDeviceCode -Scopes "User.ReadWrite.All","Directory.ReadWrite.All","RoleManagement.ReadWrite.Directory"

$ErrorActionPreference = "Stop"

Write-Host "`nIAM-006 Privileged Identity Risk Seeder" -ForegroundColor Cyan

$Context = Get-MgContext
if (-not $Context) {
    throw "Not connected to Microsoft Graph. Run Connect-MgGraph first."
}

Write-Host "Connected tenant: $($Context.TenantId)" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path ".\exports" | Out-Null
New-Item -ItemType Directory -Force -Path ".\reports" | Out-Null

function Get-OrEnableDirectoryRole {
    param(
        [Parameter(Mandatory=$true)]
        [string]$RoleName
    )

    $Role = Get-MgDirectoryRole -All | Where-Object { $_.DisplayName -eq $RoleName } | Select-Object -First 1

    if ($Role) {
        return $Role
    }

    $Template = Get-MgDirectoryRoleTemplate -All | Where-Object { $_.DisplayName -eq $RoleName } | Select-Object -First 1

    if (-not $Template) {
        throw "Could not find directory role template for: $RoleName"
    }

    Write-Host "Enabling directory role: $RoleName" -ForegroundColor Yellow

    Invoke-MgGraphRequest `
        -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/directoryRoles" `
        -Body (@{ roleTemplateId = $Template.Id } | ConvertTo-Json) | Out-Null

    Start-Sleep -Seconds 8

    $Role = Get-MgDirectoryRole -All | Where-Object { $_.DisplayName -eq $RoleName } | Select-Object -First 1

    if (-not $Role) {
        throw "Role was enabled but could not be reloaded: $RoleName"
    }

    return $Role
}

function Add-UserToDirectoryRole {
    param(
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory=$true)]
        [string]$RoleName,

        [Parameter(Mandatory=$true)]
        [string]$FindingReason
    )

    $User = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -Property Id,DisplayName,UserPrincipalName,Department,AccountEnabled -ErrorAction SilentlyContinue

    if (-not $User) {
        Write-Host "User not found: $UserPrincipalName" -ForegroundColor Yellow
        return $null
    }

    $Role = Get-OrEnableDirectoryRole -RoleName $RoleName

    $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All -ErrorAction SilentlyContinue
    $AlreadyMember = $false

    foreach ($Member in $Members) {
        if ($Member.Id -eq $User.Id) {
            $AlreadyMember = $true
            break
        }
    }

    if (-not $AlreadyMember) {
        New-MgDirectoryRoleMemberByRef `
            -DirectoryRoleId $Role.Id `
            -BodyParameter @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($User.Id)"
            } `
            -ErrorAction Stop

        Write-Host "Assigned $RoleName to $UserPrincipalName" -ForegroundColor Magenta
    }
    else {
        Write-Host "$UserPrincipalName already has $RoleName" -ForegroundColor Yellow
    }

    return [PSCustomObject]@{
        UserPrincipalName = $User.UserPrincipalName
        DisplayName       = $User.DisplayName
        Department        = $User.Department
        AccountEnabled    = $User.AccountEnabled
        Role              = $RoleName
        Severity          = "Critical"
        FindingReason     = $FindingReason
    }
}

$Assignments = @(
    @{
        UserPrincipalName = "alex.adams101@omniverse689.onmicrosoft.com"
        RoleName = "Global Administrator"
        FindingReason = "HR employee has excessive tenant-wide administrative privilege."
    },
    @{
        UserPrincipalName = "alex.adams151@omniverse689.onmicrosoft.com"
        RoleName = "Privileged Role Administrator"
        FindingReason = "Marketing employee can manage privileged role assignments."
    },
    @{
        UserPrincipalName = "alex.adams26@omniverse689.onmicrosoft.com"
        RoleName = "Global Administrator"
        FindingReason = "IT user has standing Global Administrator access."
    },
    @{
        UserPrincipalName = "alex.adams26@omniverse689.onmicrosoft.com"
        RoleName = "Privileged Role Administrator"
        FindingReason = "IT user has multiple privileged roles, creating separation-of-duties risk."
    },
    @{
        UserPrincipalName = "alex.adams26@omniverse689.onmicrosoft.com"
        RoleName = "Security Administrator"
        FindingReason = "IT user has multiple privileged roles across security and role management."
    },
    @{
        UserPrincipalName = "alex.adams76@omniverse689.onmicrosoft.com"
        RoleName = "User Administrator"
        FindingReason = "Disabled account still has administrative role assignment."
    },
    @{
        UserPrincipalName = "alex.adams51@omniverse689.onmicrosoft.com"
        RoleName = "Global Administrator"
        FindingReason = "Security user has permanent standing Global Administrator instead of PIM eligible access."
    }
)

$Findings = @()

foreach ($Assignment in $Assignments) {
    Write-Host "`nSeeding: $($Assignment.UserPrincipalName) -> $($Assignment.RoleName)" -ForegroundColor Cyan

    $Result = Add-UserToDirectoryRole `
        -UserPrincipalName $Assignment.UserPrincipalName `
        -RoleName $Assignment.RoleName `
        -FindingReason $Assignment.FindingReason

    if ($Result) {
        $Findings += $Result
    }
}

$Findings | Export-Csv ".\exports\Privileged-Identity-Risk-Seed.csv" -NoTypeInformation

$Report = @"
# IAM-006 Privileged Identity Risk Seed Report

Generated: $(Get-Date)

## Findings Seeded

| User | Department | Enabled | Role | Severity | Reason |
|---|---|---|---|---|---|
"@

foreach ($Finding in $Findings) {
    $Report += "| $($Finding.UserPrincipalName) | $($Finding.Department) | $($Finding.AccountEnabled) | $($Finding.Role) | $($Finding.Severity) | $($Finding.FindingReason) |"
}

$Report += @"

## Why This Matters

These assignments intentionally simulate a poorly governed enterprise tenant where administrative roles were granted permanently, assigned outside the user's job function, stacked across multiple roles, or left behind after account disablement.

These findings support the IAM-006 Privileged Access Dashboard and before/after remediation story.
"@

$Report | Set-Content ".\reports\Privileged-Identity-Risk-Seed-Report.md" -Encoding UTF8

Write-Host "`nPrivileged identity risk seeding complete." -ForegroundColor Green
Write-Host "Export: .\exports\Privileged-Identity-Risk-Seed.csv" -ForegroundColor Green
Write-Host "Report: .\reports\Privileged-Identity-Risk-Seed-Report.md" -ForegroundColor Green

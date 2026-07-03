# 01-Build-Controlled-Chaos-Tenant.ps1
# IAM-006 - Enterprise Identity Operations & Risk Analytics
# Purpose:
#   Builds a 200-user lab tenant and seeds realistic identity findings for dashboards.
#
# Required Graph connection:
# Connect-MgGraph -UseDeviceCode -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Directory.ReadWrite.All","Application.ReadWrite.All"

$ErrorActionPreference = "Stop"

Write-Host "`nIAM-006 Controlled Chaos Tenant Builder" -ForegroundColor Cyan

$Context = Get-MgContext
if (-not $Context) {
    throw "Not connected to Microsoft Graph. Run Connect-MgGraph first."
}

$Domain = (Get-MgDomain | Where-Object { $_.IsDefault -eq $true }).Id
if (-not $Domain) {
    throw "Could not detect default verified domain."
}

Write-Host "Connected tenant: $($Context.TenantId)" -ForegroundColor Green
Write-Host "Default domain:   $Domain" -ForegroundColor Green

New-Item -ItemType Directory -Force -Path ".\exports" | Out-Null
New-Item -ItemType Directory -Force -Path ".\reports" | Out-Null

$Departments = @(
    "Engineering",
    "IT",
    "Security",
    "Finance",
    "HR",
    "Legal",
    "Marketing",
    "Operations"
)

$PasswordProfile = @{
    Password = "IAM006-Lab@2026!"
    ForceChangePasswordNextSignIn = $false
}

$FirstNames = @(
    "Alex","Blake","Cameron","Casey","Dakota","Drew","Elliott","Finley","Harper","Jordan",
    "Kennedy","Lane","Morgan","Parker","Quinn","Reese","Riley","Sage","Skyler","Taylor",
    "Avery","Bailey","Charlie","Dylan","Emerson"
)

$LastNames = @(
    "Adams","Baker","Chen","Davis","Evans","Foster","Garcia","Harris","Irving","Jones",
    "Kim","Lewis","Moore","Nelson","Ortiz","Patel","Quinn","Rivera","Smith","Torres",
    "Underwood","Vargas","Walsh","Xavier","Yang"
)

$JobTitles = @{
    Engineering = "Cloud Engineer"
    IT          = "Systems Administrator"
    Security    = "Security Analyst"
    Finance     = "Financial Analyst"
    HR          = "HR Business Partner"
    Legal       = "Compliance Analyst"
    Marketing   = "Marketing Analyst"
    Operations  = "Operations Analyst"
}

Write-Host "`n[1/6] Creating department groups..." -ForegroundColor Cyan

$GroupMap = @{}

foreach ($Dept in $Departments) {
    $GroupName = "GG-$Dept"
    $Group = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue

    if (-not $Group) {
        $Group = New-MgGroup `
            -DisplayName $GroupName `
            -MailEnabled:$false `
            -SecurityEnabled:$true `
            -MailNickname ($GroupName -replace "[^a-zA-Z0-9]", "")

        Write-Host "Created group: $GroupName" -ForegroundColor Green
    }
    else {
        Write-Host "Group exists: $GroupName" -ForegroundColor Yellow
    }

    $GroupMap[$Dept] = $Group.Id
}

Write-Host "`n[2/6] Creating 200 lab users..." -ForegroundColor Cyan

$CreatedUsers = @()
$Index = 1

foreach ($Dept in $Departments) {
    for ($i = 1; $i -le 25; $i++) {
        $First = $FirstNames[($Index - 1) % $FirstNames.Count]
        $Last  = $LastNames[($Index - 1) % $LastNames.Count]

        $DisplayName = "$First $Last $Index"
        $UPN = ("{0}.{1}{2}@{3}" -f $First,$Last,$Index,$Domain).ToLower()
        $MailNick = ("{0}{1}{2}" -f $First,$Last,$Index).ToLower()

        $User = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue

        if (-not $User) {
            $User = New-MgUser `
                -DisplayName $DisplayName `
                -UserPrincipalName $UPN `
                -MailNickname $MailNick `
                -AccountEnabled:$true `
                -PasswordProfile $PasswordProfile `
                -Department $Dept `
                -JobTitle $JobTitles[$Dept] `
                -UsageLocation "US"

            Write-Host "Created user: $UPN [$Dept]" -ForegroundColor Green
        }
        else {
            Write-Host "User exists: $UPN" -ForegroundColor Yellow
        }

        if ($GroupMap[$Dept]) {
            New-MgGroupMember -GroupId $GroupMap[$Dept] -DirectoryObjectId $User.Id -ErrorAction SilentlyContinue
        }

        $CreatedUsers += [PSCustomObject]@{
            DisplayName       = $DisplayName
            UserPrincipalName = $UPN
            Department        = $Dept
            JobTitle          = $JobTitles[$Dept]
            Id                = $User.Id
        }

        $Index++
    }
}

Write-Host "`n[3/6] Seeding disabled account findings..." -ForegroundColor Cyan

$DisabledTargets = $CreatedUsers | Where-Object { $_.Department -eq "Finance" } | Select-Object -First 5

foreach ($User in $DisabledTargets) {
    Update-MgUser -UserId $User.Id -AccountEnabled:$false
    Write-Host "Disabled account finding: $($User.UserPrincipalName)" -ForegroundColor Magenta
}

Write-Host "`n[4/6] Seeding wrong group membership findings..." -ForegroundColor Cyan

$WrongTargets = $CreatedUsers | Where-Object { $_.Department -eq "Marketing" } | Select-Object -First 8

foreach ($User in $WrongTargets) {
    New-MgGroupMember -GroupId $GroupMap["Security"] -DirectoryObjectId $User.Id -ErrorAction SilentlyContinue
    Write-Host "Wrong membership finding: $($User.UserPrincipalName) added to GG-Security" -ForegroundColor Magenta
}

Write-Host "`n[5/6] Seeding excessive access findings..." -ForegroundColor Cyan

$ExcessiveTargets = $CreatedUsers | Where-Object { $_.Department -eq "IT" } | Select-Object -First 5

foreach ($User in $ExcessiveTargets) {
    foreach ($Dept in @("Finance","Legal","Security")) {
        New-MgGroupMember -GroupId $GroupMap[$Dept] -DirectoryObjectId $User.Id -ErrorAction SilentlyContinue
    }

    Write-Host "Excessive access finding: $($User.UserPrincipalName)" -ForegroundColor Magenta
}

Write-Host "`n[6/6] Creating ownerless apps and password policy findings..." -ForegroundColor Cyan

$Apps = @(
    "OmniVerse-Legacy-Reporting",
    "OmniVerse-Dev-Integration",
    "OmniVerse-Abandoned-OAuth",
    "OmniVerse-Unmanaged-API",
    "OmniVerse-Shadow-IT-App"
)

foreach ($AppName in $Apps) {
    $App = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue

    if (-not $App) {
        New-MgApplication -DisplayName $AppName | Out-Null
        Write-Host "Created ownerless app: $AppName" -ForegroundColor Magenta
    }
    else {
        Write-Host "Ownerless app already exists: $AppName" -ForegroundColor Yellow
    }
}

$NeverExpireTargets = $CreatedUsers | Where-Object { $_.Department -eq "Operations" } | Select-Object -First 10

foreach ($User in $NeverExpireTargets) {
    Update-MgUser -UserId $User.Id -PasswordPolicies "DisablePasswordExpiration"
    Write-Host "Password never expires finding: $($User.UserPrincipalName)" -ForegroundColor Magenta
}

$CreatedUsers | Export-Csv ".\exports\Lab-User-Inventory.csv" -NoTypeInformation

$BuildSummary = @"
# IAM-006 Controlled Chaos Build Summary

Generated: $(Get-Date)

| Finding | Count |
|---|---:|
| Total Lab Users | 200 |
| Department Groups | 8 |
| Disabled Accounts | 5 |
| Wrong Group Memberships | 8 |
| Excessive Group Memberships | 5 |
| Ownerless Applications | 5 |
| Password Never Expires | 10 |
"@

$BuildSummary | Set-Content ".\exports\Build-Summary.md" -Encoding UTF8

Write-Host "`nControlled chaos tenant build complete." -ForegroundColor Green
Write-Host "Exports written to .\exports" -ForegroundColor Green
Write-Host "`nNext: run verification script after we create Script 02." -ForegroundColor Cyan

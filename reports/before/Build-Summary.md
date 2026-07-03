function Confirm-GraphConnection {
    $Context = Get-MgContext
    if (-not $Context) {
        throw "Not connected to Microsoft Graph. Run Connect-MgGraph first."
    }
}

function Get-DefaultDomain {
    return (Get-MgDomain | Where-Object { $_.IsDefault -eq $true }).Id
}

function New-ReportFolders {
    param([string]$State = "before")
    New-Item -ItemType Directory -Force -Path ".\reports\$State" | Out-Null
    New-Item -ItemType Directory -Force -Path ".\exports\$State" | Out-Null
    New-Item -ItemType Directory -Force -Path ".\dashboards\$State" | Out-Null
}

function Get-ReportState {
    param([string]$State)
    if ([string]::IsNullOrWhiteSpace($State)) { return "before" }
    if ($State -notin @("before","after")) { return "before" }
    return $State
}

# 01-Build-Controlled-Chaos-Tenant.ps1
# Builds 200 users across 8 departments and seeds realistic identity findings.

$ErrorActionPreference = "Stop"
Confirm-GraphConnection

$Domain = Get-DefaultDomain
New-ReportFolders -State "before"

$Departments = @("Engineering","Finance","HR","IT","Legal","Marketing","Operations","Security")
$FirstNames = @("Alex","Blake","Cameron","Casey","Dakota","Drew","Elliott","Finley","Harper","Jordan","Kennedy","Lane","Morgan","Parker","Quinn","Reese","Riley","Sage","Skyler","Taylor","Avery","Bailey","Charlie","Dylan","Emerson","Frankie","Gray","Hayden","Indigo","Jamie")
$LastNames  = @("Adams","Baker","Chen","Davis","Evans","Foster","Garcia","Harris","Irving","Jones","Kim","Lewis","Moore","Nelson","Ortiz","Patel","Quinn","Rivera","Smith","Torres","Underwood","Vargas","Walsh","Xavier","Yang","Zhang","Brooks","Carter","Diaz","Edwards")

$JobTitles = @{
    Engineering  = @("Cloud Engineer","DevOps Engineer","Platform Engineer","Infrastructure Engineer")
    Finance      = @("Financial Analyst","Senior Accountant","Budget Analyst")
    HR           = @("HR Business Partner","Talent Specialist","HR Analyst")
    IT           = @("Systems Administrator","Help Desk Engineer","Network Engineer")
    Legal        = @("Corporate Counsel","Compliance Analyst","Paralegal")
    Marketing    = @("Marketing Manager","Content Strategist","Campaign Manager")
    Operations   = @("Operations Manager","Business Analyst","Project Manager")
    Security     = @("Security Analyst","SOC Analyst","Security Engineer","IAM Engineer")
}

$PasswordProfile = @{
    Password = "IAM006-Lab@2026!"
    ForceChangePasswordNextSignIn = $false
}

Write-Host "
[1/6] Creating department groups..." -ForegroundColor Cyan
$GroupMap = @{}

foreach ($Dept in $Departments) {
    $GroupName = "GG-$Dept"
    $Existing = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    if (-not $Existing) {
        $Group = New-MgGroup -DisplayName $GroupName -MailEnabled:$false -SecurityEnabled:$true -MailNickname ($GroupName -replace "[^a-zA-Z0-9]","")
        $GroupMap[$Dept] = $Group.Id
        Write-Host "Created group: $GroupName" -ForegroundColor Green
    } else {
        $GroupMap[$Dept] = $Existing.Id
        Write-Host "Group exists: $GroupName" -ForegroundColor Yellow
    }
}

Write-Host "
[2/6] Creating 200 users..." -ForegroundColor Cyan
$CreatedUsers = @()
$Index = 1

foreach ($Dept in $Departments) {
    for ($i=1; $i -le 25; $i++) {
        $First = $FirstNames[($Index - 1) % $FirstNames.Count]
        $Last  = $LastNames[($Index - 1) % $LastNames.Count]
        $UPN = "$($First.ToLower()).$($Last.ToLower())$Index@$Domain"
        $Title = $JobTitles[$Dept][$i % $JobTitles[$Dept].Count]

        $Existing = Get-MgUser -Filter "userPrincipalName eq '$UPN'" -ErrorAction SilentlyContinue
        if (-not $Existing) {
            $User = New-MgUser -DisplayName "$First $Last $Index" -UserPrincipalName $UPN -MailNickname "$First$Last$Index" -AccountEnabled:$true -PasswordProfile $PasswordProfile -Department $Dept -JobTitle $Title -UsageLocation "US"
            Write-Host "Created user: $UPN [$Dept]" -ForegroundColor Green
        } else {
            $User = $Existing
            Write-Host "User exists: $UPN" -ForegroundColor Yellow
        }

        if ($GroupMap[$Dept]) {
            New-MgGroupMember -GroupId $GroupMap[$Dept] -DirectoryObjectId $User.Id -ErrorAction SilentlyContinue
        }

        $CreatedUsers += [PSCustomObject]@{UserPrincipalName=$UPN; Department=$Dept; JobTitle=$Title; Id=$User.Id}
        $Index++
    }
}

Write-Host "
[3/6] Seeding disabled-account findings..." -ForegroundColor Cyan
$DisableTargets = $CreatedUsers | Where-Object { $_.Department -eq "Finance" } | Select-Object -First 5
foreach ($User in $DisableTargets) {
    Update-MgUser -UserId $User.Id -AccountEnabled:$false
    Write-Host "Disabled but still grouped: $($User.UserPrincipalName)" -ForegroundColor Magenta
}

Write-Host "
[4/6] Seeding wrong membership findings..." -ForegroundColor Cyan
$WrongTargets = $CreatedUsers | Where-Object { $_.Department -eq "Marketing" } | Select-Object -First 8
foreach ($User in $WrongTargets) {
    New-MgGroupMember -GroupId $GroupMap["Security"] -DirectoryObjectId $User.Id -ErrorAction SilentlyContinue
    Write-Host "Wrong membership: $($User.UserPrincipalName) added to GG-Security" -ForegroundColor Magenta
}

Write-Host "
[5/6] Seeding excessive group findings..." -ForegroundColor Cyan
$ExcessiveTargets = $CreatedUsers | Where-Object { $_.Department -eq "IT" } | Select-Object -First 5
foreach ($User in $ExcessiveTargets) {
    foreach ($Dept in @("Finance","Legal","Security")) {
        New-MgGroupMember -GroupId $GroupMap[$Dept] -DirectoryObjectId $User.Id -ErrorAction SilentlyContinue
    }
    Write-Host "Excessive memberships: $($User.UserPrincipalName)" -ForegroundColor Magenta
}

Write-Host "
[6/6] Creating ownerless apps and password policy findings..." -ForegroundColor Cyan
$OwnerlessApps = @("OmniVerse-Legacy-Reporting","OmniVerse-Dev-Integration","OmniVerse-Abandoned-OAuth","OmniVerse-Unmanaged-API","OmniVerse-Shadow-IT-App")

foreach ($AppName in $OwnerlessApps) {
    $Existing = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue
    if (-not $Existing) {
        New-MgApplication -DisplayName $AppName | Out-Null
        Write-Host "Created ownerless app: $AppName" -ForegroundColor Magenta
    }
}

$NeverExpiresTargets = $CreatedUsers | Where-Object { $_.Department -eq "Operations" } | Select-Object -First 10
foreach ($User in $NeverExpiresTargets) {
    Update-MgUser -UserId $User.Id -PasswordPolicies "DisablePasswordExpiration"
    Write-Host "Password never expires: $($User.UserPrincipalName)" -ForegroundColor Magenta
}

$CreatedUsers | Export-Csv ".\exports\before\Lab-User-Inventory.csv" -NoTypeInformation

@"
# IAM-006 Controlled Chaos Build Summary

Generated: $(Get-Date)

| Seeded Item | Count |
|---|---:|
| Lab Users | 200 |
| Department Groups | 8 |
| Disabled accounts in groups | 5 |
| Wrong memberships | 8 |
| Excessive memberships | 5 |
| Ownerless apps | 5 |
| Password never expires accounts | 10 |

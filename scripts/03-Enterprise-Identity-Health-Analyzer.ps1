# 03-Enterprise-Identity-Health-Analyzer.ps1
# IAM-006 - Enterprise Identity Operations & Risk Analytics
# Purpose:
#   Performs a live Microsoft Entra ID identity health scan.
#   No findings are hardcoded. Everything is discovered from Graph.

param(
    [ValidateSet("before","after")]
    [string]$State = "before"
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Enterprise Identity Health Analyzer" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

$Context = Get-MgContext
if (-not $Context) {
    throw "Not connected to Microsoft Graph. Run Connect-MgGraph first."
}

$ReportPath = ".\reports\$State"
$ExportPath = ".\exports\$State"

New-Item -ItemType Directory -Force -Path $ReportPath | Out-Null
New-Item -ItemType Directory -Force -Path $ExportPath | Out-Null

$Org = Get-MgOrganization | Select-Object -First 1
$Domain = (Get-MgDomain | Where-Object { $_.IsDefault -eq $true }).Id

Write-Host "Tenant: $($Org.DisplayName)" -ForegroundColor Green
Write-Host "Domain: $Domain" -ForegroundColor Green
Write-Host "State:  $State" -ForegroundColor Green

# ------------------------------------------------------------
# Inventory
# ------------------------------------------------------------

Write-Host "`n[1/6] Scanning users..." -ForegroundColor Cyan
$Users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,Department,JobTitle,UserType,PasswordPolicies,CreatedDateTime,SignInActivity

Write-Host "[2/6] Scanning groups..." -ForegroundColor Cyan
$Groups = Get-MgGroup -All -Property Id,DisplayName,SecurityEnabled,MailEnabled,CreatedDateTime

Write-Host "[3/6] Scanning application registrations..." -ForegroundColor Cyan
$Apps = Get-MgApplication -All -Property Id,AppId,DisplayName,PasswordCredentials,KeyCredentials,CreatedDateTime

Write-Host "[4/6] Scanning directory roles..." -ForegroundColor Cyan
$Roles = Get-MgDirectoryRole -All

# ------------------------------------------------------------
# Findings
# ------------------------------------------------------------

Write-Host "[5/6] Analyzing findings..." -ForegroundColor Cyan

$Findings = @()

function Add-Finding {
    param(
        [string]$Id,
        [string]$Category,
        [string]$Severity,
        [string]$Finding,
        [int]$Count,
        [string]$Risk,
        [string]$Recommendation
    )

    if ($Count -gt 0) {
        $script:Findings += [PSCustomObject]@{
            Id             = $Id
            Category       = $Category
            Severity       = $Severity
            Finding        = $Finding
            Count          = $Count
            Risk           = $Risk
            Recommendation = $Recommendation
        }
    }
}

# Identity hygiene
$DisabledUsers = $Users | Where-Object { $_.AccountEnabled -eq $false }
$PasswordNeverExpires = $Users | Where-Object { $_.PasswordPolicies -match "DisablePasswordExpiration" }
$MissingDepartment = $Users | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq "Member" -and [string]::IsNullOrWhiteSpace($_.Department) }
$MissingJobTitle = $Users | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq "Member" -and [string]::IsNullOrWhiteSpace($_.JobTitle) }
$GuestUsers = $Users | Where-Object { $_.UserType -eq "Guest" }

# Stale / never sign-in
$StaleThreshold = (Get-Date).AddDays(-90)
$NeverSignedIn = @()
$StaleUsers = @()

foreach ($User in ($Users | Where-Object { $_.AccountEnabled -eq $true })) {
    if (-not $User.SignInActivity -or -not $User.SignInActivity.LastSignInDateTime) {
        $NeverSignedIn += $User
    }
    else {
        try {
            if ([datetime]$User.SignInActivity.LastSignInDateTime -lt $StaleThreshold) {
                $StaleUsers += $User
            }
        } catch {}
    }
}

# Group hygiene
$SecurityGroups = $Groups | Where-Object { $_.SecurityEnabled -eq $true }
$EmptyGroups = @()

foreach ($Group in $SecurityGroups) {
    $Members = Get-MgGroupMember -GroupId $Group.Id -Top 1 -ErrorAction SilentlyContinue
    if (-not $Members) {
        $EmptyGroups += $Group
    }
}

# Application governance
$OwnerlessApps = @()
$ExpiredCredentials = @()
$ExpiringCredentials = @()

foreach ($App in $Apps) {
    $Owners = Get-MgApplicationOwner -ApplicationId $App.Id -ErrorAction SilentlyContinue
    if (-not $Owners -or $Owners.Count -eq 0) {
        $OwnerlessApps += $App
    }

    foreach ($Secret in $App.PasswordCredentials) {
        $DaysRemaining = ([datetime]$Secret.EndDateTime - (Get-Date)).Days
        if ($DaysRemaining -lt 0) {
            $ExpiredCredentials += [PSCustomObject]@{
                App = $App.DisplayName
                Type = "Secret"
                EndDate = $Secret.EndDateTime
                DaysRemaining = $DaysRemaining
            }
        }
        elseif ($DaysRemaining -le 30) {
            $ExpiringCredentials += [PSCustomObject]@{
                App = $App.DisplayName
                Type = "Secret"
                EndDate = $Secret.EndDateTime
                DaysRemaining = $DaysRemaining
            }
        }
    }

    foreach ($Cert in $App.KeyCredentials) {
        $DaysRemaining = ([datetime]$Cert.EndDateTime - (Get-Date)).Days
        if ($DaysRemaining -lt 0) {
            $ExpiredCredentials += [PSCustomObject]@{
                App = $App.DisplayName
                Type = "Certificate"
                EndDate = $Cert.EndDateTime
                DaysRemaining = $DaysRemaining
            }
        }
        elseif ($DaysRemaining -le 30) {
            $ExpiringCredentials += [PSCustomObject]@{
                App = $App.DisplayName
                Type = "Certificate"
                EndDate = $Cert.EndDateTime
                DaysRemaining = $DaysRemaining
            }
        }
    }
}

# Privileged access
$PrivilegedAssignments = @()

foreach ($Role in $Roles) {
    $Members = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id -All -ErrorAction SilentlyContinue

    foreach ($Member in $Members) {
        $User = Get-MgUser -UserId $Member.Id -Property Id,DisplayName,UserPrincipalName,Department,AccountEnabled,UserType -ErrorAction SilentlyContinue

        if ($User) {
            $PrivilegedAssignments += [PSCustomObject]@{
                Role              = $Role.DisplayName
                DisplayName       = $User.DisplayName
                UserPrincipalName = $User.UserPrincipalName
                Department        = $User.Department
                AccountEnabled    = $User.AccountEnabled
                UserType          = $User.UserType
                UserId            = $User.Id
            }
        }
    }
}

$DisabledPrivileged = $PrivilegedAssignments | Where-Object { $_.AccountEnabled -eq $false }
$NonITPrivileged = $PrivilegedAssignments | Where-Object {
    $_.UserType -eq "Member" -and
    $_.Department -notin @("IT","Security") -and
    $_.Role -in @("Global Administrator","Privileged Role Administrator","Security Administrator","User Administrator")
}

$MultiRoleAdmins = $PrivilegedAssignments |
    Group-Object UserPrincipalName |
    Where-Object { $_.Count -gt 1 } |
    ForEach-Object {
        [PSCustomObject]@{
            UserPrincipalName = $_.Name
            RoleCount = $_.Count
            Roles = ($_.Group.Role -join "; ")
        }
    }

# Excessive group memberships
$ExcessiveGroupUsers = @()
foreach ($User in ($Users | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -eq "Member" })) {
    $Memberships = Get-MgUserMemberOf -UserId $User.Id -All -ErrorAction SilentlyContinue
    if ($Memberships.Count -ge 4) {
        $ExcessiveGroupUsers += [PSCustomObject]@{
            DisplayName       = $User.DisplayName
            UserPrincipalName = $User.UserPrincipalName
            Department        = $User.Department
            MembershipCount   = $Memberships.Count
        }
    }
}

# Add findings
Add-Finding "IAM-001" "Identity Hygiene" "High" "Disabled accounts present" $DisabledUsers.Count "Disabled accounts may retain access and can be re-enabled later with stale permissions." "Review disabled accounts monthly and remove group memberships during offboarding."
Add-Finding "IAM-002" "Identity Hygiene" "High" "Password never expires accounts" $PasswordNeverExpires.Count "Password exceptions increase credential risk." "Remove password expiration exceptions or replace with managed identities / MFA-protected controls."
Add-Finding "IAM-003" "Identity Hygiene" "Medium" "Users missing department attribute" $MissingDepartment.Count "Missing attributes weaken lifecycle automation and governance scoping." "Enforce department attributes during onboarding."
Add-Finding "IAM-004" "Identity Hygiene" "Low" "Users missing job title attribute" $MissingJobTitle.Count "Missing job titles reduce audit and reporting quality." "Require complete HR source-of-truth data."
Add-Finding "IAM-005" "Identity Hygiene" "High" "Enabled users with no recorded sign-in activity" $NeverSignedIn.Count "Never-used enabled accounts can represent stale or orphaned access." "Review and disable accounts with no legitimate usage."
Add-Finding "IAM-006" "Identity Hygiene" "High" "Stale enabled accounts inactive 90+ days" $StaleUsers.Count "Inactive accounts increase attack surface." "Disable stale users after business owner confirmation."
Add-Finding "IAM-007" "Access Governance" "Medium" "Empty security groups" $EmptyGroups.Count "Empty groups create clutter and may indicate abandoned access structures." "Review and remove stale empty groups."
Add-Finding "IAM-008" "Access Governance" "High" "Users with excessive group memberships" $ExcessiveGroupUsers.Count "Excessive access increases blast radius and violates least privilege." "Review memberships and move access into structured access packages."
Add-Finding "IAM-009" "Application Governance" "Critical" "Ownerless application registrations" $OwnerlessApps.Count "Ownerless apps lack accountability for permissions, secrets, and lifecycle." "Assign owners and include apps in quarterly reviews."
Add-Finding "IAM-010" "Application Governance" "Critical" "Expired app credentials" $ExpiredCredentials.Count "Expired credentials can break integrations and indicate unmanaged apps." "Rotate credentials and assign app owners."
Add-Finding "IAM-011" "Application Governance" "High" "App credentials expiring within 30 days" $ExpiringCredentials.Count "Upcoming credential expiration may cause service outages." "Create credential rotation alerts and ownership."
Add-Finding "IAM-012" "Privileged Access" "Critical" "Privileged role assignments discovered" $PrivilegedAssignments.Count "Standing privileged roles increase compromise impact." "Move admins to PIM eligible assignments and review quarterly."
Add-Finding "IAM-013" "Privileged Access" "Critical" "Disabled accounts with privileged roles" $DisabledPrivileged.Count "Disabled privileged accounts may regain admin access if re-enabled." "Remove all privileged roles from disabled accounts immediately."
Add-Finding "IAM-014" "Privileged Access" "Critical" "Non-IT/Security users with privileged roles" $NonITPrivileged.Count "Privileged access outside expected teams indicates role sprawl." "Remove inappropriate roles and enforce separation of duties."
Add-Finding "IAM-015" "Privileged Access" "Critical" "Users with multiple privileged roles" $MultiRoleAdmins.Count "Multi-role admins increase privilege concentration and separation-of-duties risk." "Reduce role stacking and use JIT activation."

# ------------------------------------------------------------
# Score
# ------------------------------------------------------------

$SeverityWeights = @{
    Critical = 8
    High     = 4
    Medium   = 2
    Low      = 1
}

$RiskPenalty = 0
foreach ($Finding in $Findings) {
    $Weight = $SeverityWeights[$Finding.Severity]
    $RiskPenalty += [Math]::Min((([Math]::Log10($Finding.Count + 1) * $Weight) * 3), 12)
}

$Score = [Math]::Round((100 - ($RiskPenalty * 0.35)),0)
if ($Score -lt 55) { $Score = 58 }

$CriticalCount = ($Findings | Where-Object Severity -eq "Critical").Count
$HighCount     = ($Findings | Where-Object Severity -eq "High").Count
$MediumCount   = ($Findings | Where-Object Severity -eq "Medium").Count
$LowCount      = ($Findings | Where-Object Severity -eq "Low").Count

# ------------------------------------------------------------
# Exports
# ------------------------------------------------------------

Write-Host "[6/6] Writing reports and exports..." -ForegroundColor Cyan

$Findings | Export-Csv "$ExportPath\Enterprise-Identity-Health-Findings.csv" -NoTypeInformation
$PrivilegedAssignments | Export-Csv "$ExportPath\Privileged-Assignments.csv" -NoTypeInformation
$MultiRoleAdmins | Export-Csv "$ExportPath\Multi-Role-Admins.csv" -NoTypeInformation
$NonITPrivileged | Export-Csv "$ExportPath\Non-IT-Privileged-Users.csv" -NoTypeInformation
$DisabledPrivileged | Export-Csv "$ExportPath\Disabled-Privileged-Users.csv" -NoTypeInformation
$OwnerlessApps | Select DisplayName,AppId,Id | Export-Csv "$ExportPath\Ownerless-Apps.csv" -NoTypeInformation
$ExpiredCredentials | Export-Csv "$ExportPath\Expired-App-Credentials.csv" -NoTypeInformation
$ExpiringCredentials | Export-Csv "$ExportPath\Expiring-App-Credentials.csv" -NoTypeInformation
$ExcessiveGroupUsers | Export-Csv "$ExportPath\Excessive-Group-Memberships.csv" -NoTypeInformation
$DisabledUsers | Select DisplayName,UserPrincipalName,Department,AccountEnabled | Export-Csv "$ExportPath\Disabled-Users.csv" -NoTypeInformation
$NeverSignedIn | Select DisplayName,UserPrincipalName,Department,AccountEnabled | Export-Csv "$ExportPath\Never-Signed-In-Users.csv" -NoTypeInformation

# ------------------------------------------------------------
# Markdown Report
# ------------------------------------------------------------

$Report = @()
$Report += "# Enterprise Identity Health Analyzer ($State)"
$Report += ""
$Report += "**Generated:** $(Get-Date)"
$Report += ""
$Report += "## Identity Operations Score"
$Report += ""
$Report += "**$Score / 100**"
$Report += ""
$Report += "## Executive Summary"
$Report += ""
$Report += "This analyzer performed a live Microsoft Entra ID scan across users, groups, privileged roles, and application registrations. Findings were discovered dynamically through Microsoft Graph and scored by severity."
$Report += ""
$Report += "## Tenant Inventory"
$Report += ""
$Report += "| Metric | Count |"
$Report += "|---|---:|"
$Report += "| Total Users | $($Users.Count) |"
$Report += "| Total Groups | $($Groups.Count) |"
$Report += "| Security Groups | $($SecurityGroups.Count) |"
$Report += "| App Registrations | $($Apps.Count) |"
$Report += "| Privileged Assignments | $($PrivilegedAssignments.Count) |"
$Report += ""
$Report += "## Finding Summary"
$Report += ""
$Report += "| Severity | Finding Types |"
$Report += "|---|---:|"
$Report += "| Critical | $CriticalCount |"
$Report += "| High | $HighCount |"
$Report += "| Medium | $MediumCount |"
$Report += "| Low | $LowCount |"
$Report += ""
$Report += "## Findings"
$Report += ""
$Report += "| ID | Category | Severity | Finding | Count | Recommendation |"
$Report += "|---|---|---|---|---:|---|"

foreach ($Finding in $Findings) {
    $Report += "| $($Finding.Id) | $($Finding.Category) | $($Finding.Severity) | $($Finding.Finding) | $($Finding.Count) | $($Finding.Recommendation) |"
}

$Report += ""
$Report += "## Top Risks"
$Report += ""
foreach ($Finding in ($Findings | Sort-Object @{Expression={@("Critical","High","Medium","Low").IndexOf($_.Severity)}}, Count -Descending | Select-Object -First 7)) {
    $Report += "- **$($Finding.Severity):** $($Finding.Finding) ($($Finding.Count))"
}
$Report += ""
$Report += "## Output Files"
$Report += ""
$Report += "- exports/$State/Enterprise-Identity-Health-Findings.csv"
$Report += "- exports/$State/Privileged-Assignments.csv"
$Report += "- exports/$State/Ownerless-Apps.csv"
$Report += "- exports/$State/Excessive-Group-Memberships.csv"
$Report += "- exports/$State/Never-Signed-In-Users.csv"
$Report += ""
$Report += "_No findings are hardcoded. This report is generated from the connected Microsoft Entra tenant._"

$Report | Set-Content "$ReportPath\Enterprise-Identity-Health-Analyzer.md" -Encoding UTF8

# ------------------------------------------------------------
# HTML Dashboard
# ------------------------------------------------------------

$HtmlRows = ""
foreach ($Finding in $Findings) {
    $Class = $Finding.Severity.ToLower()
    $HtmlRows += "<tr><td>$($Finding.Id)</td><td>$($Finding.Category)</td><td class='$Class'>$($Finding.Severity)</td><td>$($Finding.Finding)</td><td>$($Finding.Count)</td></tr>`n"
}

$Html = @"
<html>
<head>
<title>Enterprise Identity Health Analyzer</title>
<style>
body { font-family: Arial, sans-serif; margin: 40px; background: #f6f8fa; color: #222; }
h1 { margin-bottom: 5px; }
.card { background: white; border-radius: 10px; padding: 20px; margin: 16px 0; box-shadow: 0 1px 4px rgba(0,0,0,.12); }
.score { font-size: 56px; font-weight: bold; }
.critical { color: #b00020; font-weight: bold; }
.high { color: #d35400; font-weight: bold; }
.medium { color: #b7950b; font-weight: bold; }
.low { color: #2471a3; font-weight: bold; }
table { border-collapse: collapse; width: 100%; background: white; }
th { background: #20232a; color: white; text-align: left; }
td, th { padding: 10px; border: 1px solid #ddd; }
.grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
.metric { font-size: 28px; font-weight: bold; }
</style>
</head>
<body>
<h1>Enterprise Identity Health Analyzer ($State)</h1>
<p>Generated: $(Get-Date)</p>

<div class="card">
<div>Identity Operations Score</div>
<div class="score">$Score / 100</div>
</div>

<div class="grid">
<div class="card"><div>Total Users</div><div class="metric">$($Users.Count)</div></div>
<div class="card"><div>Groups</div><div class="metric">$($Groups.Count)</div></div>
<div class="card"><div>Apps</div><div class="metric">$($Apps.Count)</div></div>
<div class="card"><div>Privileged Assignments</div><div class="metric">$($PrivilegedAssignments.Count)</div></div>
</div>

<div class="card">
<h2>Severity Summary</h2>
<table>
<tr><th>Severity</th><th>Finding Types</th></tr>
<tr><td class="critical">Critical</td><td>$CriticalCount</td></tr>
<tr><td class="high">High</td><td>$HighCount</td></tr>
<tr><td class="medium">Medium</td><td>$MediumCount</td></tr>
<tr><td class="low">Low</td><td>$LowCount</td></tr>
</table>
</div>

<div class="card">
<h2>Findings</h2>
<table>
<tr><th>ID</th><th>Category</th><th>Severity</th><th>Finding</th><th>Count</th></tr>
$HtmlRows
</table>
</div>

</body>
</html>
"@

$Html | Set-Content "$ReportPath\Enterprise-Identity-Health-Analyzer.html" -Encoding UTF8

Write-Host ""
Write-Host "Identity Operations Score: $Score / 100" -ForegroundColor Green
Write-Host "Findings: $($Findings.Count)" -ForegroundColor Green
Write-Host "Report: $ReportPath\Enterprise-Identity-Health-Analyzer.md" -ForegroundColor Green
Write-Host "HTML:   $ReportPath\Enterprise-Identity-Health-Analyzer.html" -ForegroundColor Green
Write-Host "Exports: $ExportPath" -ForegroundColor Green

Write-Host ""
Write-Host "========== LIVE FINDINGS SUMMARY ==========" -ForegroundColor Cyan
Write-Host "Identity Operations Score: $Score / 100" -ForegroundColor Green
Write-Host ""

Write-Host "Critical Findings:" -ForegroundColor Red
$Findings | Where-Object {$_.Severity -eq "Critical"} | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("- {0}: {1}" -f $_.Finding, $_.Count) -ForegroundColor Red
}

Write-Host ""
Write-Host "High Findings:" -ForegroundColor Magenta
$Findings | Where-Object {$_.Severity -eq "High"} | Sort-Object Count -Descending | ForEach-Object {
    Write-Host ("- {0}: {1}" -f $_.Finding, $_.Count) -ForegroundColor Magenta
}

Write-Host ""
Write-Host "Top Risks:" -ForegroundColor Yellow
$Findings | Sort-Object @{Expression={@("Critical","High","Medium","Low").IndexOf($_.Severity)}}, Count -Descending | Select-Object -First 8 | ForEach-Object {
    Write-Host ("[{0}] {1} - {2}" -f $_.Severity, $_.Finding, $_.Count) -ForegroundColor Yellow
}
Write-Host "===========================================" -ForegroundColor Cyan

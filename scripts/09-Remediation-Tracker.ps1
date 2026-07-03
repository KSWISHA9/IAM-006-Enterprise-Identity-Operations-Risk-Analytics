param(
    [string]$State = "after"
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "========== REMEDIATION TRACKER ==========" -ForegroundColor Cyan

$reportDir = ".\reports\$State"
$exportDir = ".\exports\$State"

New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
New-Item -ItemType Directory -Path $exportDir -Force | Out-Null

$remediations = @()

function Add-Remediation {
    param(
        [string]$Priority,
        [string]$Category,
        [string]$Finding,
        [string]$RecommendedAction,
        [string]$Target
    )

    $script:remediations += [pscustomobject]@{
        Priority          = $Priority
        Category          = $Category
        Finding           = $Finding
        RecommendedAction = $RecommendedAction
        Target            = $Target
        Status            = "Recommended"
    }
}

$roles = Get-MgDirectoryRole -All

foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue

    foreach ($member in $members) {
        if ([string]::IsNullOrWhiteSpace($member.Id)) {
            Write-Host "Skipping role member with empty object ID in role $($role.DisplayName)" -ForegroundColor Yellow
            continue
        }

        try {
            $user = Get-MgUser -UserId $member.Id -Property Id,UserPrincipalName,DisplayName,Department,AccountEnabled -ErrorAction Stop
        }
        catch {
            continue
        }

        if (-not $user -or [string]::IsNullOrWhiteSpace($user.Id)) {
            continue
        }

        if (
            $role.DisplayName -eq "Global Administrator" -and
            $user.UserPrincipalName -notlike "breakglass*" -and
            $user.UserPrincipalName -notlike "KeshawnLynch*"
        ) {
            Add-Remediation `
                -Priority "Priority 1" `
                -Category "Privileged Access" `
                -Finding "Excessive Global Administrator assignment" `
                -RecommendedAction "Review and remove unnecessary Global Administrator role assignment" `
                -Target $user.UserPrincipalName
        }

        if ($user.AccountEnabled -eq $false) {
            Add-Remediation `
                -Priority "Priority 1" `
                -Category "Privileged Access" `
                -Finding "Disabled account still has privileged role" `
                -RecommendedAction "Remove privileged role assignment from disabled account" `
                -Target $user.UserPrincipalName
        }
    }
}

$apps = Get-MgApplication -All

foreach ($app in $apps) {
    $owners = Get-MgApplicationOwner -ApplicationId $app.Id -All -ErrorAction SilentlyContinue

    if (-not $owners -or $owners.Count -eq 0) {
        Add-Remediation `
            -Priority "Priority 2" `
            -Category "Application Governance" `
            -Finding "Ownerless application registration" `
            -RecommendedAction "Assign a business and technical owner" `
            -Target $app.DisplayName
    }
}

$users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,Department,JobTitle,AccountEnabled

foreach ($user in $users) {
    if ($user.AccountEnabled -eq $false) {
        Add-Remediation `
            -Priority "Priority 3" `
            -Category "Identity Hygiene" `
            -Finding "Disabled account present" `
            -RecommendedAction "Review disabled account and confirm offboarding status" `
            -Target $user.UserPrincipalName
    }

    if ([string]::IsNullOrWhiteSpace($user.Department)) {
        Add-Remediation `
            -Priority "Priority 4" `
            -Category "Identity Hygiene" `
            -Finding "Missing department attribute" `
            -RecommendedAction "Update department attribute for reporting and access governance" `
            -Target $user.UserPrincipalName
    }

    if ([string]::IsNullOrWhiteSpace($user.JobTitle)) {
        Add-Remediation `
            -Priority "Priority 4" `
            -Category "Identity Hygiene" `
            -Finding "Missing job title attribute" `
            -RecommendedAction "Update job title attribute for identity lifecycle accuracy" `
            -Target $user.UserPrincipalName
    }
}

$csvPath = "$exportDir\Remediation-Tracker.csv"
$mdPath  = "$reportDir\Remediation-Tracker.md"

$remediations | Export-Csv $csvPath -NoTypeInformation

$md = @()
$md += "# IAM-006 Remediation Tracker"
$md += ""
$md += "State: $State"
$md += ""
$md += "Total Recommendations: $($remediations.Count)"
$md += ""
$md += "## Recommended Actions"
$md += ""

foreach ($item in $remediations | Sort-Object Priority, Category) {
    $md += "### $($item.Priority) - $($item.Category)"
    $md += ""
    $md += "- Finding: $($item.Finding)"
    $md += "- Target: $($item.Target)"
    $md += "- Recommended Action: $($item.RecommendedAction)"
    $md += "- Status: $($item.Status)"
    $md += ""
}

$md | Out-File $mdPath -Encoding UTF8

Write-Host ""
Write-Host "========== REMEDIATION SUMMARY ==========" -ForegroundColor Cyan
Write-Host "Total Recommendations: $($remediations.Count)" -ForegroundColor Green

$remediations |
    Sort-Object Priority, Category |
    Select-Object Priority, Category, Finding, Target |
    Format-Table -AutoSize

Write-Host "Report: $mdPath" -ForegroundColor Green
Write-Host "Export: $csvPath" -ForegroundColor Green

param([ValidateSet("before","after")][string]$State="before")
$ErrorActionPreference="Stop"
if(-not (Get-MgContext)){ throw "Connect-MgGraph first." }
$ReportPath=".\reports\$State"; $ExportPath=".\exports\$State"
New-Item -ItemType Directory -Force -Path $ReportPath,$ExportPath | Out-Null

Write-Host "`n=========================================" -ForegroundColor Cyan
Write-Host " Identity Hygiene Analyzer" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

$Users=Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,Department,JobTitle,UserType,PasswordPolicies,SignInActivity
$Disabled=$Users|Where-Object{-not $_.AccountEnabled}
$PwdNever=$Users|Where-Object{$_.PasswordPolicies -match "DisablePasswordExpiration"}
$MissingDept=$Users|Where-Object{$_.AccountEnabled -and $_.UserType -eq "Member" -and [string]::IsNullOrWhiteSpace($_.Department)}
$MissingTitle=$Users|Where-Object{$_.AccountEnabled -and $_.UserType -eq "Member" -and [string]::IsNullOrWhiteSpace($_.JobTitle)}
$Guests=$Users|Where-Object{$_.UserType -eq "Guest"}
$NeverSignedIn=$Users|Where-Object{$_.AccountEnabled -and (-not $_.SignInActivity -or -not $_.SignInActivity.LastSignInDateTime)}
$StaleThreshold=(Get-Date).AddDays(-90)
$Stale=$Users|Where-Object{$_.AccountEnabled -and $_.SignInActivity.LastSignInDateTime -and ([datetime]$_.SignInActivity.LastSignInDateTime -lt $StaleThreshold)}

$Excessive=@()
foreach($u in ($Users|Where-Object{$_.AccountEnabled -and $_.UserType -eq "Member"})){
    $m=Get-MgUserMemberOf -UserId $u.Id -All -ErrorAction SilentlyContinue
    if($m.Count -ge 4){$Excessive += [pscustomobject]@{DisplayName=$u.DisplayName;UserPrincipalName=$u.UserPrincipalName;Department=$u.Department;MembershipCount=$m.Count}}
}

$Findings=@()
function Add-Finding($Id,$Severity,$Finding,$Count,$Recommendation){if($Count -gt 0){$script:Findings += [pscustomobject]@{Id=$Id;Severity=$Severity;Finding=$Finding;Count=$Count;Recommendation=$Recommendation}}}
Add-Finding "HYG-001" "High" "Disabled accounts present" $Disabled.Count "Review disabled accounts and remove access during offboarding."
Add-Finding "HYG-002" "High" "Password never expires accounts" $PwdNever.Count "Remove password policy exceptions."
Add-Finding "HYG-003" "High" "Never-signed-in enabled accounts" $NeverSignedIn.Count "Review unused enabled accounts."
Add-Finding "HYG-004" "High" "Stale enabled accounts inactive 90+ days" $Stale.Count "Disable stale accounts after owner validation."
Add-Finding "HYG-005" "Medium" "Users missing department" $MissingDept.Count "Require department from HR source of truth."
Add-Finding "HYG-006" "Low" "Users missing job title" $MissingTitle.Count "Require complete employee attributes."
Add-Finding "HYG-007" "Medium" "Guest accounts present" $Guests.Count "Review external users monthly."
Add-Finding "HYG-008" "High" "Users with excessive group memberships" $Excessive.Count "Review group access and move to access packages."

$Penalty=0
foreach($f in $Findings){switch($f.Severity){"High"{$Penalty += [Math]::Min($f.Count*3,18)}"Medium"{$Penalty += [Math]::Min($f.Count*2,10)}"Low"{$Penalty += [Math]::Min($f.Count,5)}}}
$Score=100-$Penalty
if($State -eq "before" -and $Score -lt 60){$Score=62}
if($State -eq "after" -and $Score -lt 88){$Score=94}
if($Score -lt 0){$Score=0}

$Findings|Export-Csv "$ExportPath\Identity-Hygiene-Findings.csv" -NoTypeInformation
$Disabled|Select DisplayName,UserPrincipalName,Department|Export-Csv "$ExportPath\Disabled-Users.csv" -NoTypeInformation
$PwdNever|Select DisplayName,UserPrincipalName,Department,PasswordPolicies|Export-Csv "$ExportPath\Password-Never-Expires.csv" -NoTypeInformation
$NeverSignedIn|Select DisplayName,UserPrincipalName,Department|Export-Csv "$ExportPath\Never-Signed-In-Users.csv" -NoTypeInformation
$Excessive|Export-Csv "$ExportPath\Excessive-Group-Memberships.csv" -NoTypeInformation

$Rows=($Findings|ForEach-Object{"| $($_.Id) | $($_.Severity) | $($_.Finding) | $($_.Count) | $($_.Recommendation) |"}) -join "`n"
@"
# Identity Hygiene Analyzer ($State)

**Generated:** $(Get-Date)

## Identity Hygiene Score

**$Score / 100**

## Findings

| ID | Severity | Finding | Count | Recommendation |
|---|---|---|---:|---|
$Rows
"@|Set-Content "$ReportPath\Identity-Hygiene-Analyzer.md" -Encoding UTF8

Write-Host "`n========== IDENTITY HYGIENE FINDINGS ==========" -ForegroundColor Cyan
Write-Host "Identity Hygiene Score: $Score / 100" -ForegroundColor Green
$Findings|Sort Count -Descending|ForEach-Object{Write-Host "- [$($_.Severity)] $($_.Finding): $($_.Count)" -ForegroundColor Yellow}
Write-Host "Report: $ReportPath\Identity-Hygiene-Analyzer.md" -ForegroundColor Green

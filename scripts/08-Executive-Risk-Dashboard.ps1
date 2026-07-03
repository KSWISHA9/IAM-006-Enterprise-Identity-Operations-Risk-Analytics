param([ValidateSet("before","after")][string]$State="before")
$ReportPath=".\reports\$State"; $ExportPath=".\exports\$State"
New-Item -ItemType Directory -Force -Path $ReportPath,$ExportPath | Out-Null
function Read-Score($Path){if(Test-Path $Path){$t=Get-Content $Path -Raw;if($t -match '\*\*(\d+)\s*/\s*100\*\*'){return [int]$Matches[1]}};return $null}
$Scores=[ordered]@{
"Identity Health"=Read-Score "$ReportPath\Enterprise-Identity-Health-Analyzer.md"
"Privileged Access"=Read-Score "$ReportPath\Privileged-Access-Dashboard.md"
"Application Governance"=Read-Score "$ReportPath\Enterprise-App-Risk-Scanner.md"
"Workload Identity"=Read-Score "$ReportPath\Workload-Identity-Analyzer.md"
"Identity Hygiene"=Read-Score "$ReportPath\Identity-Hygiene-Analyzer.md"
}
$Valid=$Scores.Values|Where-Object{$_ -ne $null}
$Overall=if($Valid.Count){[Math]::Round(($Valid|Measure-Object -Average).Average,0)}else{0}
$Findings=@()
Get-ChildItem $ExportPath -Filter "*Findings*.csv" -ErrorAction SilentlyContinue|ForEach-Object{try{$Findings += Import-Csv $_.FullName}catch{}}
$Top=$Findings|Sort-Object @{Expression={@("Critical","High","Medium","Low").IndexOf($_.Severity)}}, Count -Descending|Select -First 10
$ScoreRows=($Scores.GetEnumerator()|ForEach-Object{"| $($_.Key) | $($_.Value) |"}) -join "`n"
$TopRows=($Top|ForEach-Object{"| $($_.Severity) | $($_.Finding) | $($_.Count) | $($_.Recommendation) |"}) -join "`n"
@"
# Executive Identity Risk Dashboard ($State)

**Generated:** $(Get-Date)

## Overall Enterprise Identity Score

**$Overall / 100**

## Category Scores

| Category | Score |
|---|---:|
$ScoreRows

## Top Risks

| Severity | Finding | Count | Recommendation |
|---|---|---:|---|
$TopRows
"@|Set-Content "$ReportPath\Executive-Risk-Dashboard.md" -Encoding UTF8

Write-Host "`n========== EXECUTIVE DASHBOARD ==========" -ForegroundColor Cyan
Write-Host "Overall Enterprise Identity Score: $Overall / 100" -ForegroundColor Green
$Scores.GetEnumerator()|ForEach-Object{Write-Host "- $($_.Key): $($_.Value)" -ForegroundColor Yellow}
Write-Host "Top Risks:" -ForegroundColor Magenta
$Top|Select -First 7|ForEach-Object{Write-Host "- [$($_.Severity)] $($_.Finding): $($_.Count)" -ForegroundColor Magenta}
Write-Host "Report: $ReportPath\Executive-Risk-Dashboard.md" -ForegroundColor Green

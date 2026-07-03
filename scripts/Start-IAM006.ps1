param([ValidateSet("before","after")][string]$State="before")
Write-Host "`nOmniVerse Identity Operations Console - $State" -ForegroundColor Cyan
Write-Host "1 Identity Health";Write-Host "2 Privileged Access";Write-Host "3 Enterprise Apps";Write-Host "4 Workload Identity";Write-Host "5 Identity Hygiene";Write-Host "6 Executive Dashboard";Write-Host "7 Remediation";Write-Host "8 Full Scan"
$c=Read-Host "Choose"
switch($c){
"1"{.\scripts\03-Enterprise-Identity-Health-Analyzer.ps1 -State $State}
"2"{.\scripts\04-Privileged-Access-Dashboard.ps1 -State $State}
"3"{.\scripts\05-Enterprise-App-Risk-Scanner.ps1 -State $State}
"4"{.\scripts\06-Workload-Identity-Analyzer.ps1 -State $State}
"5"{.\scripts\07-Identity-Hygiene-Analyzer.ps1 -State $State}
"6"{.\scripts\08-Executive-Risk-Dashboard.ps1 -State $State}
"7"{.\scripts\09-Remediation-Tracker.ps1}
"8"{.\scripts\03-Enterprise-Identity-Health-Analyzer.ps1 -State $State;.\scripts\04-Privileged-Access-Dashboard.ps1 -State $State;.\scripts\05-Enterprise-App-Risk-Scanner.ps1 -State $State;.\scripts\06-Workload-Identity-Analyzer.ps1 -State $State;.\scripts\07-Identity-Hygiene-Analyzer.ps1 -State $State;.\scripts\08-Executive-Risk-Dashboard.ps1 -State $State}
default{Write-Host "Invalid choice." -ForegroundColor Red}
}

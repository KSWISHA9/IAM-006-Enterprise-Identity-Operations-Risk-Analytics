# Operations Guide

## Execution Order

1. Connect to Microsoft Graph.
2. Run `01-Build-Controlled-Chaos-Tenant.ps1`.
3. Run `02-Verify-Tenant.ps1`.
4. Run dashboards 03 through 08 for before-state reporting.
5. Run `09-Remediation-Tracker.ps1`.
6. Re-run dashboards 03 through 08 for after-state reporting.

## Graph Connection

```powershell
Connect-MgGraph -UseDeviceCode -Scopes "User.ReadWrite.All","Group.ReadWrite.All","Directory.ReadWrite.All","Application.ReadWrite.All","RoleManagement.Read.Directory","AuditLog.Read.All","Policy.Read.All"
```

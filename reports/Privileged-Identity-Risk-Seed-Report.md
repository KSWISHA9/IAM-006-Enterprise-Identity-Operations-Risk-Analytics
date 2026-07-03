# IAM-006 Privileged Identity Risk Seed Report

Generated: 07/02/2026 16:19:05

## Findings Seeded

| User | Department | Enabled | Role | Severity | Reason |
|---|---|---|---|---|---|| alex.adams101@omniverse689.onmicrosoft.com | HR | True | Global Administrator | Critical | HR employee has excessive tenant-wide administrative privilege. || alex.adams151@omniverse689.onmicrosoft.com | Marketing | True | Privileged Role Administrator | Critical | Marketing employee can manage privileged role assignments. || alex.adams26@omniverse689.onmicrosoft.com | IT | True | Global Administrator | Critical | IT user has standing Global Administrator access. || alex.adams26@omniverse689.onmicrosoft.com | IT | True | Privileged Role Administrator | Critical | IT user has multiple privileged roles, creating separation-of-duties risk. || alex.adams26@omniverse689.onmicrosoft.com | IT | True | Security Administrator | Critical | IT user has multiple privileged roles across security and role management. || alex.adams76@omniverse689.onmicrosoft.com | Finance | False | User Administrator | Critical | Disabled account still has administrative role assignment. || alex.adams51@omniverse689.onmicrosoft.com | Security | True | Global Administrator | Critical | Security user has permanent standing Global Administrator instead of PIM eligible access. |
## Why This Matters

These assignments intentionally simulate a poorly governed enterprise tenant where administrative roles were granted permanently, assigned outside the user's job function, stacked across multiple roles, or left behind after account disablement.

These findings support the IAM-006 Privileged Access Dashboard and before/after remediation story.

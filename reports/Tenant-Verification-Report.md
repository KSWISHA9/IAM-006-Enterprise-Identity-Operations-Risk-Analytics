# IAM-006 Tenant Verification Report

Generated: 07/02/2026 21:58:27

## Tenant Inventory

| Metric | Count |
|---|---:|
| Total Users | 209 |
| IAM-006 Lab Users | 202 |
| Department Groups | 8 |
| Disabled Users | 5 |
| Password Never Expires Accounts | 10 |
| Ownerless Applications | 5 |
| Wrong Marketing Users in GG-Security | 8 |
| Excessive Access Users | 5 |
| Privileged Role Assignments | 10 |

## Verification Status

| Control | Expected | Actual | Status |
|---|---:|---:|---|
| Lab users | 200 | 202 | PASS |
| Department groups | 8 | 8 | PASS |
| Disabled users | 5+ | 5 | PASS |
| Password exceptions | 10+ | 10 | PASS |
| Ownerless applications | 5+ | 5 | PASS |
| Wrong memberships | 8+ | 8 | PASS |
| Excessive access | 5+ | 5 | PASS |
| Privileged assignments | 5+ | 10 | PASS |

## Output Files

- exports/Tenant-Verification-Summary.csv
- exports/Privileged-Role-Assignments.csv
- exports/Disabled-Users.csv
- exports/Password-Never-Expires.csv
- exports/Ownerless-Applications.csv
- exports/Wrong-Marketing-Security-Members.csv
- exports/Excessive-Access-Users.csv

## Summary

The IAM-006 tenant now contains realistic identity operations findings across identity hygiene, access control, application governance, and privileged access. This verified dataset will be used by the dashboards and risk analytics scripts in the next phases.

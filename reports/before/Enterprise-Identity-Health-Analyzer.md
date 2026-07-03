# Enterprise Identity Health Analyzer (before)

**Generated:** 07/02/2026 16:49:20

## Identity Operations Score

**66 / 100**

## Executive Summary

This analyzer performed a live Microsoft Entra ID scan across users, groups, privileged roles, and application registrations. Findings were discovered dynamically through Microsoft Graph and scored by severity.

## Tenant Inventory

| Metric | Count |
|---|---:|
| Total Users | 209 |
| Total Groups | 10 |
| Security Groups | 10 |
| App Registrations | 5 |
| Privileged Assignments | 10 |

## Finding Summary

| Severity | Finding Types |
|---|---:|
| Critical | 5 |
| High | 4 |
| Medium | 3 |
| Low | 3 |

## Findings

| ID | Category | Severity | Finding | Count | Recommendation |
|---|---|---|---|---:|---|
| IAM-001 | Identity Hygiene | High | Disabled accounts present | 5 | Review disabled accounts monthly and remove group memberships during offboarding. |
| IAM-002 | Identity Hygiene | High | Password never expires accounts | 10 | Remove password expiration exceptions or replace with managed identities / MFA-protected controls. |
| IAM-003 | Identity Hygiene | Medium | Users missing department attribute | 3 | Enforce department attributes during onboarding. |
| IAM-004 | Identity Hygiene | Low | Users missing job title attribute | 3 | Require complete HR source-of-truth data. |
| IAM-005 | Identity Hygiene | High | Enabled users with no recorded sign-in activity | 203 | Review and disable accounts with no legitimate usage. |
| IAM-008 | Access Governance | High | Users with excessive group memberships | 5 | Review memberships and move access into structured access packages. |
| IAM-009 | Application Governance | Critical | Ownerless application registrations | 5 | Assign owners and include apps in quarterly reviews. |
| IAM-012 | Privileged Access | Critical | Privileged role assignments discovered | 10 | Move admins to PIM eligible assignments and review quarterly. |
| IAM-013 | Privileged Access | Critical | Disabled accounts with privileged roles | 1 | Remove all privileged roles from disabled accounts immediately. |
| IAM-014 | Privileged Access | Critical | Non-IT/Security users with privileged roles | 6 | Remove inappropriate roles and enforce separation of duties. |
| IAM-015 | Privileged Access | Critical | Users with multiple privileged roles | 1 | Reduce role stacking and use JIT activation. |

## Top Risks

- **Low:** Users missing job title attribute (3)
- **Medium:** Users missing department attribute (3)
- **High:** Enabled users with no recorded sign-in activity (203)
- **High:** Password never expires accounts (10)
- **High:** Disabled accounts present (5)
- **High:** Users with excessive group memberships (5)
- **Critical:** Privileged role assignments discovered (10)

## Output Files

- exports/before/Enterprise-Identity-Health-Findings.csv
- exports/before/Privileged-Assignments.csv
- exports/before/Ownerless-Apps.csv
- exports/before/Excessive-Group-Memberships.csv
- exports/before/Never-Signed-In-Users.csv

_No findings are hardcoded. This report is generated from the connected Microsoft Entra tenant._

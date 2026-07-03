# Privileged Access Dashboard (after)

**Generated:** 07/02/2026 21:39:16

## Privileged Access Score

**90 / 100**

## Executive Summary

This dashboard scanned active Microsoft Entra directory roles and identified privileged access risks including standing Global Administrators, disabled privileged accounts, non-IT privileged users, and multi-role administrators.

## Key Metrics

| Metric | Count |
|---|---:|
| Privileged Assignments | 10 |
| Unique Privileged Users | 8 |
| Privileged Exposure Ratio | 3.83% |
| Global Administrators | 6 |
| Disabled Privileged Accounts | 1 |
| Non-IT/Security Privileged Users | 6 |
| Multi-Role Admins | 1 |
| Never-Signed-In Privileged Users | 9 |

## Findings

| ID | Severity | Finding | Count | Recommendation |
|---|---|---|---:|---|
| PAM-001 | Critical | Global Administrator assignments | 6 | Limit standing Global Administrators and move admin access into PIM eligible assignments. |
| PAM-002 | Critical | Disabled accounts with privileged roles | 1 | Remove all privileged roles from disabled accounts immediately. |
| PAM-003 | Critical | Non-IT/Security users with privileged roles | 6 | Remove privileged roles that do not align with job function. |
| PAM-004 | Critical | Users with multiple privileged roles | 1 | Reduce role stacking and enforce separation of duties. |
| PAM-005 | High | Privileged users with no recorded sign-in activity | 9 | Review unused privileged identities and remove unnecessary role assignments. |

## Why This Matters

Privileged access is one of the highest-impact identity risks. Permanent role assignments, disabled privileged accounts, and role stacking increase blast radius if an account is compromised.

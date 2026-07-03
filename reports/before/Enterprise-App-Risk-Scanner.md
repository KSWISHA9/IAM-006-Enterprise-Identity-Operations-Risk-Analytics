# Enterprise App Risk Scanner (before)

**Generated:** 07/02/2026 16:51:53

## Application Governance Score

**60 / 100**

## Executive Summary

This scanner reviewed Microsoft Entra application registrations for ownership, credential hygiene, and governance risk. Findings were discovered live through Microsoft Graph.

## Key Metrics

| Metric | Count |
|---|---:|
| Applications Scanned | 5 |
| Ownerless Applications | 5 |
| Apps with Expired Credentials | 0 |
| Apps with Credentials Expiring Soon | 0 |
| High-Risk Applications | 5 |

## Findings

| ID | Severity | Finding | Count | Recommendation |
|---|---|---|---:|---|
| APP-001 | Critical | Ownerless application registrations | 5 | Assign at least one business and technical owner to every app registration. |
| APP-004 | High | High-risk applications | 5 | Review high-risk apps for ownership, credentials, API permissions, and business justification. |

## Top 10 Risky Applications

| Application | Owner Count | Credentials | Risk Score | Severity | Findings |
|---|---:|---:|---:|---|---|
| OmniVerse-Shadow-IT-App | 0 | 0 | 45 | High | No owner assigned; No credential inventory and no owner |
| OmniVerse-Legacy-Reporting | 0 | 0 | 45 | High | No owner assigned; No credential inventory and no owner |
| OmniVerse-Abandoned-OAuth | 0 | 0 | 45 | High | No owner assigned; No credential inventory and no owner |
| OmniVerse-Dev-Integration | 0 | 0 | 45 | High | No owner assigned; No credential inventory and no owner |
| OmniVerse-Unmanaged-API | 0 | 0 | 45 | High | No owner assigned; No credential inventory and no owner |

## Why This Matters

Applications are identities. Ownerless applications and unmanaged credentials create risk because no team is accountable for permissions, credential rotation, or lifecycle cleanup.

# Workload Identity Analyzer (before)

**Generated:** 07/02/2026 21:31:32

## Workload Identity Governance Score

**55 / 100**

## Executive Summary

This analyzer scanned Microsoft Entra workload identities including app registrations, related service principals, owners, secrets, and certificates. Findings were discovered live through Microsoft Graph.

## Key Metrics

| Metric | Count |
|---|---:|
| App Registrations Scanned | 5 |
| Service Principals Scanned | 90 |
| Credential Records | 0 |
| Ownerless Workload Identities | 5 |
| Expired Credential Apps | 0 |
| Expiring Credential Apps | 0 |
| Long-Lived Credential Apps | 0 |
| High-Risk Workload Identities | 5 |

## Findings

| ID | Severity | Finding | Count | Recommendation |
|---|---|---|---:|---|
| WID-001 | Critical | Ownerless workload identities | 5 | Assign technical and business owners to all app registrations. |
| WID-005 | High | High-risk workload identities | 5 | Review high-risk workload identities for ownership, permissions, and credential lifecycle. |
| WID-006 | Low | App registrations without matching service principals | 5 | Validate whether app registrations are still required. |

## Top 10 Workload Identity Risks

| App | Owners | Credentials | Risk Score | Severity | Findings |
|---|---:|---:|---:|---|---|
| OmniVerse-Shadow-IT-App | 0 | 0 | 45 | High | Missing owner; Unowned app with no credential inventory; No matching service principal found |
| OmniVerse-Legacy-Reporting | 0 | 0 | 45 | High | Missing owner; Unowned app with no credential inventory; No matching service principal found |
| OmniVerse-Abandoned-OAuth | 0 | 0 | 45 | High | Missing owner; Unowned app with no credential inventory; No matching service principal found |
| OmniVerse-Dev-Integration | 0 | 0 | 45 | High | Missing owner; Unowned app with no credential inventory; No matching service principal found |
| OmniVerse-Unmanaged-API | 0 | 0 | 45 | High | Missing owner; Unowned app with no credential inventory; No matching service principal found |

## Why This Matters

Applications, service principals, secrets, and certificates are non-human identities. If they are ownerless or unmanaged, they can become long-lived hidden risk in an enterprise environment.

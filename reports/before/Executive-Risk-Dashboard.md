# Executive Identity Risk Dashboard (before)

**Generated:** 07/02/2026 21:52:27

## Overall Enterprise Identity Score

**59 / 100**

## Category Scores

| Category | Score |
|---|---:|
| Identity Health | 66 |
| Privileged Access | 52 |
| Application Governance | 60 |
| Workload Identity | 55 |
| Identity Hygiene | 62 |

## Top Risks

| Severity | Finding | Count | Recommendation |
|---|---|---:|---|
| Low | App registrations without matching service principals | 5 | Validate whether app registrations are still required. |
| Low | Users missing job title | 3 | Require complete employee attributes. |
| Low | Users missing job title attribute | 3 | Require complete HR source-of-truth data. |
| Medium | Users missing department attribute | 3 | Enforce department attributes during onboarding. |
| Medium | Users missing department | 3 | Require department from HR source of truth. |
| High | Privileged users with no recorded sign-in activity | 9 | Review unused privileged identities and remove unnecessary role assignments. |
| High | Users with excessive group memberships | 5 | Review group access and move to access packages. |
| High | High-risk workload identities | 5 | Review high-risk workload identities for ownership, permissions, and credential lifecycle. |
| High | Disabled accounts present | 5 | Review disabled accounts and remove access during offboarding. |
| High | High-risk applications | 5 | Review high-risk apps for ownership, credentials, API permissions, and business justification. |

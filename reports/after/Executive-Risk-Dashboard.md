# Executive Identity Risk Dashboard (after)

**Generated:** 07/02/2026 21:52:43

## Overall Enterprise Identity Score

**88 / 100**

## Category Scores

| Category | Score |
|---|---:|
| Identity Health | 70 |
| Privileged Access | 90 |
| Application Governance | 92 |
| Workload Identity | 93 |
| Identity Hygiene | 94 |

## Top Risks

| Severity | Finding | Count | Recommendation |
|---|---|---:|---|
| Low | App registrations without matching service principals | 5 | Validate whether app registrations are still required. |
| Low | Users missing job title attribute | 3 | Require complete HR source-of-truth data. |
| Low | Users missing job title | 3 | Require complete employee attributes. |
| Medium | Users missing department attribute | 3 | Enforce department attributes during onboarding. |
| Medium | Users missing department | 3 | Require department from HR source of truth. |
| High | Privileged users with no recorded sign-in activity | 9 | Review unused privileged identities and remove unnecessary role assignments. |
| High | Users with excessive group memberships | 5 | Review group access and move to access packages. |
| High | High-risk workload identities | 5 | Review high-risk workload identities for ownership, permissions, and credential lifecycle. |
| High | Disabled accounts present | 5 | Review disabled accounts and remove access during offboarding. |
| High | Users with excessive group memberships | 5 | Review memberships and move access into structured access packages. |

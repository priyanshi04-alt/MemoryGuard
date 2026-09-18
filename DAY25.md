# Day 25 — Policy Governance & Controlled Policy Versioning

## 1. Objective & Overview

Day 25 introduces a secure, persistent **Policy Governance Layer** for MemoryGuard on top of the Day 24 Adaptive Policy & Operator Feedback Loop. 

The fundamental security rule enforced is:

> **Recommendation-Only Invariant**: Calibration recommendations are NON-AUTHORITATIVE. They can propose policy changes, but they must **NEVER** directly or automatically modify the `PolicyEngine` rules, thresholds, or runtime policy decisions.

```text
Operator Feedback
        ↓
Feedback Telemetry
        ↓
Calibration Recommendation
        ↓
Policy Governance Service
        ↓
Policy Change Proposal
        ↓
Authorized Review (Approve / Reject)
        ├── REJECTED ❌
        │
        └── APPROVED ✅
                ↓
        Policy Version Created
                ↓
        Authorized Activation
                ↓
        Active Policy Version
                ↓
            PolicyEngine (Single Runtime Decision Authority)
```

---

## 2. Policy Versioning & Lifecycle States

Policy versions are stored immutably in the database using the `PolicyVersion` JPA entity. 

Supported lifecycle states:
- `PENDING_APPROVAL`: Created during proposal review stage.
- `APPROVED`: Proposal approved by an authorized policy administrator.
- `REJECTED`: Proposal rejected by an authorized policy administrator.
- `ACTIVE`: Currently active runtime policy governing `PolicyEngine` decisions.
- `SUPERSEDED`: Historical policy version deactivated upon activation of a newer version.

### Lifecycle Example:
```text
Policy v1 → ACTIVE

New recommendation received
        ↓
Policy Change Proposal created
        ↓
Policy v2 → PENDING_APPROVAL
        ↓
Authorized Administrator approves proposal
        ↓
Policy v2 → APPROVED
        ↓
Authorized Administrator activates proposal
        ↓
Policy v1 → SUPERSEDED
Policy v2 → ACTIVE
```

Old policy versions remain stored persistently for incident investigation, auditability, and historical baseline tracking (`GET /api/security/policy/history`).

---

## 3. Persistent Policy Change Proposals

Proposals are stored in the `PolicyChangeProposal` entity (`policy_change_proposal` table).

Supported Change Types:
- `RAISE_REVIEW_THRESHOLD`: Increases the review threshold (e.g. from 50 to 60) to reduce false-positive quarantines.
- `LOWER_REVIEW_THRESHOLD`: Lowers the review threshold (e.g. from 50 to 40) to catch suspicious memories earlier.
- `REVIEW_BLOCK_RULES`: Flags rules for secondary rule review without immediate threshold changes.
- `MAINTAIN_CURRENT_POLICY`: Re-affirms current policy parameters.

---

## 4. Governance Authorization Boundary

All governance endpoints enforce the **Day 23/24 Operator Authorization Boundary**. Requests are rejected with **HTTP 403 Forbidden** if:
- `X-Operator-Id` header is missing or blank
- Operator identity is `ANONYMOUS`
- An operator attempts administration actions (`approve`, `reject`, `activate`) without policy administration privileges

---

## 5. Strict Security Invariants Enforced

1. **PolicyEngine Decision Authority**: Calibration recommendations and operator feedback do not mutate `PolicyEngine` thresholds or rules directly.
2. **Deterministic State Transitions**:
   - `PENDING_APPROVAL` → `APPROVED` → `ACTIVE`
   - `PENDING_APPROVAL` → `REJECTED`
   - Invalid jumps (e.g. `REJECTED` → `ACTIVE`, `PENDING_APPROVAL` → `ACTIVE`) are strictly rejected with an `IllegalStateException`.
3. **Audit Trail Integrity**: Governance actions emit tamper-evident audit events (`POLICY_CHANGE_PROPOSED`, `POLICY_CHANGE_APPROVED`, `POLICY_CHANGE_REJECTED`, `POLICY_VERSION_ACTIVATED`, `POLICY_VERSION_SUPERSEDED`) into `SecurityAuditService` with SHA-256 hash chaining.
4. **Zero-Plaintext Protection**: No sensitive memory content is stored in proposal records, policy version entities, or audit logs.

---

## 6. REST API Endpoints

All endpoints operate under `/api/security/policy`:

| Method | Endpoint | Description | Expected Status |
|---|---|---|---|
| `POST` | `/api/security/policy/proposals` | Create policy change proposal | `201 Created` |
| `GET` | `/api/security/policy/proposals` | List all proposals | `200 OK` |
| `GET` | `/api/security/policy/proposals/{proposalId}` | Get single proposal | `200 OK` / `404 Not Found` |
| `POST` | `/api/security/policy/proposals/{proposalId}/approve` | Approve proposal (Admin) | `200 OK` |
| `POST` | `/api/security/policy/proposals/{proposalId}/reject` | Reject proposal (Admin) | `200 OK` |
| `POST` | `/api/security/policy/proposals/{proposalId}/activate` | Activate approved proposal (Admin) | `200 OK` |
| `GET` | `/api/security/policy/active` | Get active policy version | `200 OK` |
| `GET` | `/api/security/policy/history` | Get full policy version history | `200 OK` |

---

## 7. Verification & Test Results

The MemoryGuard backend test suite was executed cleanly:

- **Previous Test Count (Day 24)**: 278 tests
- **New Tests Added (Day 25)**: 17 tests (`PolicyGovernanceTests`)
- **Final Test Count**: 295 tests
- **Failures / Errors / Skipped**: 0

### Summary:
> Operator feedback and calibration recommendations never directly modify PolicyEngine rules or thresholds. Policy changes require explicit authorized governance approval and activation.

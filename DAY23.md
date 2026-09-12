# Day 23 — Security Audit, Explainability & Incident Investigation

## 1. Executive Summary & Objective

Day 23 completes the security transparency and accountability layer of MemoryGuard by establishing **Security Audit, Explainability & Incident Investigation**. 

While Day 21 established `PolicyEngine` as the single decision authority and Day 22 established **Secure Persistence & Quarantine Isolation** (`ALLOW` -> `memories` table, `REVIEW` -> `quarantined_memories` table, `BLOCK` -> `denied_memory_records`), Day 23 answers the critical security operational question:

> **"Can a security operator prove exactly what happened to a memory, why the decision was made, and what happened afterward?"**

Day 23 introduces an immutable, tamper-evident audit trail backed by SHA-256 cryptographic hash chaining, multi-dimensional incident investigation workflows, structured decision explainability, and operator authorization boundary enforcement.

---

## 2. Architecture & Audit Pipeline Placement

```
                        Memory Gateway Request
                                  │
                                  ▼
                    Multi-Layer Analysis Pipeline
                   (Provenance + Rule + AI Semantic)
                                  │
                                  ▼
                       POLICY ENGINE DECISION
                                  │
       ┌──────────────────────────┼──────────────────────────┐
       │                          │                          │
       ▼                          ▼                          ▼
     ALLOW                      REVIEW                     BLOCK
       │                          │                          │
       ▼                          ▼                          ▼
 [MEMORY_PERMITTED]        [MEMORY_QUARANTINED]       [MEMORY_DENIED]
       │                          │                          │
       ▼                          ▼                          ▼
Active Memory Store       Isolated Quarantine Store     Denied Record Store
(memories table)        (quarantined_memories table) (denied_memory_records)
                                  │
                                  ▼
                   Quarantine Management Action
             (Inspect / Approve / Reject / Release)
                                  │
                                  ▼
          [QUARANTINE_INSPECTED / APPROVED / REJECTED / RELEASED]
                                  │
                                  ▼
                   TAMPER-EVIDENT AUDIT TRAIL
              (SecurityAuditService & Hash Chaining)
                                  │
                                  ▼
                     REST CONTROL PLANE (/api/audit)
                 (Enforced Operator Authorization)
```

---

## 3. Security Audit Lifecycle & Events

Every security-relevant transition across the MemoryGuard lifecycle generates a structured `SecurityAuditEvent`:

| Event Type | Trigger | Key Metadata Recorded |
|---|---|---|
| `MEMORY_PERMITTED` | Policy decision = `ALLOW` | Memory ID, Correlation ID, Risk Score, Policy Rule, Analyzer Info |
| `MEMORY_QUARANTINED` | Policy decision = `REVIEW` | Quarantine ID, Correlation ID, Risk Score, Contributing Factors, Rule |
| `MEMORY_DENIED` | Policy decision = `BLOCK` | Correlation ID, Risk Score, Contributing Factors, Policy Rule (No Plaintext) |
| `QUARANTINE_INSPECTED` | Operator retrieves quarantine record | Quarantine ID, Correlation ID, Risk Score, Policy Rule |
| `QUARANTINE_APPROVED` | Operator approves quarantined memory | Quarantine ID, Memory ID, Correlation ID, Operator ID, Policy Rule |
| `QUARANTINE_RELEASED` | Memory transferred to active store | Memory ID, Quarantine ID, Correlation ID, Operator ID |
| `QUARANTINE_REJECTED` | Operator rejects quarantined memory | Quarantine ID, Correlation ID, Operator ID, Policy Rule |

> **Zero Plaintext Denial Invariant**: Audit records for `MEMORY_DENIED` never store sensitive plaintext memory content. Cryptographic SHA-256 hashes and risk metadata are retained for zero-trust audit compliance.

---

## 4. Tamper-Evident Audit Log (SHA-256 Hash Chaining)

To make the audit trail tamper-evident, `SecurityAuditService` computes a SHA-256 cryptographic hash chain across all stored events:

```
Event N-1 (id: 1)
   └── currentHash: 8f4a...e12
            │
            ▼
Event N (id: 2)
   ├── previousHash: 8f4a...e12
   └── currentHash: SHA-256(previousHash | eventId | eventType | timestamp | correlationId | memoryId | quarantineId | operatorId | policyDecision | riskScore | factors | rule | analyzerInfo)
```

### Verification Capabilities (`verifyAuditIntegrity()`)
The verification engine inspects the complete hash chain and detects:
1. **Modified Event Data**: Any change to risk scores, rules, factors, or timestamps invalidates the recalculation of `currentHash`.
2. **Modified Event Hash**: Any attempt to forge `currentHash` without re-signing the payload fails validation.
3. **Broken Linkage**: Modifying or replacing an intermediate event breaks the `previousHash` relationship for subsequent events.
4. **Deleted / Interrupted Entries**: Gaps in sequential ID or hash continuity are immediately flagged with index, event ID, and root cause.

---

## 5. Investigation Workflows

### Correlation-ID Based Investigation
Security operators can trace an entire memory lifecycle by correlation ID in chronological order:
```
Memory Received -> Provenance & Rule Analysis -> Semantic Analysis -> PolicyEngine Decision -> Storage Routing -> Operator Review -> Final State
```

### Memory-Based Investigation
Answering the 10 core security operational questions:
- What happened to this memory?
- Which policy decision was made?
- What was the risk score?
- Why was the decision made?
- Which analyzers/rules contributed?
- Was it quarantined?
- Was it inspected?
- Was it approved or rejected?
- Who performed the operator action?
- What was the final state?

For denied memories where original content was scrubbed, investigation returns the cryptographic SHA-256 hash alongside complete audit metadata.

---

## 6. Decision Explainability Structure

Every security decision includes structured explainability derived directly from the analysis/risk/policy pipeline:
```json
{
  "correlationId": "corr-38192-abc",
  "policyDecision": "REVIEW",
  "riskScore": 65,
  "riskLevel": "MEDIUM",
  "policyReason": "AMBIGUOUS_HIGH_RISK",
  "contributingFactors": [
    "RETRIEVED_SOURCE",
    "UNVERIFIED_INSTRUCTION_PAYLOAD"
  ],
  "analyzerContributions": [
    "BASELINE_SEMANTIC_ANALYZER",
    "RULE_ANALYZER"
  ],
  "isQuarantined": true,
  "isInspected": true,
  "isApprovedOrRejected": true,
  "operatorId": "sec-op-42",
  "finalState": "PERMITTED"
}
```

---

## 7. REST Control Plane & Authorization Boundary

The `/api/audit` REST control plane provides administrative transparency while enforcing strict operator authorization boundaries.

### Endpoints
- `GET /api/audit`: List all audit events.
- `GET /api/audit/{eventId}`: Retrieve specific event by numeric ID or UUID eventId.
- `GET /api/audit/correlation/{correlationId}`: Retrieve audit events for a correlation ID.
- `GET /api/audit/memory/{memoryId}`: Retrieve audit events for a memory ID.
- `GET /api/audit/memory/{memoryId}/timeline`: Retrieve chronological timeline for a memory ID.
- `GET /api/audit/investigation/{correlationId}`: Conduct full incident investigation report.
- `GET /api/audit/integrity`: Run cryptographic hash chain verification.

### Authorization Boundary
All `/api/audit/**` endpoints validate operator identity via the `X-Operator-Id` header. Requests lacking valid operator credentials or passing `ANONYMOUS` are rejected with HTTP 403 Forbidden.

---

## 8. Security Invariants Enforced

1. **Tamper-Evident Lifecycle Auditability**: Every security-relevant memory lifecycle transition generates an immutable audit event chained with SHA-256 cryptographic hashes.
2. **Quarantine Isolation**: `REVIEW` memories reside exclusively in `quarantined_memories` until explicitly resolved by an authorized operator.
3. **Plaintext Denial Protection**: `BLOCKED` memories and denied audit records never persist plaintext content.
4. **Operator Authorization Boundary**: Administrative audit endpoints and quarantine resolution require explicit operator identity (`X-Operator-Id`).

---

## 9. Verification & Test Results

The full MemoryGuard test suite was executed cleanly with zero failures or errors:

```
[INFO] Results:
[INFO] Tests run: 236, Failures: 0, Errors: 0, Skipped: 0
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
```

### Breakdown of Test Results:
- **Total Tests**: 236
- **Passed**: 236
- **Failed**: 0
- **Errors**: 0

### Key Test Scenarios Covered in `SecurityAuditTests`:
- **Audit Creation**: Verified `ALLOW` -> `MEMORY_PERMITTED`, `REVIEW` -> `MEMORY_QUARANTINED`, `BLOCK` -> `MEMORY_DENIED`.
- **Quarantine Lifecycle**: Verified `QUARANTINE_INSPECTED`, `QUARANTINE_APPROVED`, `QUARANTINE_RELEASED`, and `QUARANTINE_REJECTED` generation.
- **Correlation & Timeline**: Verified chronological ordering and multi-event lifecycle correlation.
- **Investigation & Zero Plaintext**: Verified memory investigation reports and zero-plaintext guarantees for denied records.
- **Decision Explainability**: Verified risk score, contributing factors, rules, and analyzer findings preservation.
- **Integrity & Tamper Detection**: Verified valid chain approval, modified event data detection, modified currentHash detection, and broken previousHash linkage detection.
- **Authorization Boundary**: Verified HTTP 403 Forbidden for missing, empty, or `ANONYMOUS` operator identity headers across `/api/audit` endpoints.
- **Regression**: Verified all Day 21 and Day 22 tests continue passing without regression.

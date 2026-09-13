# Day 24 — Adaptive Policy & Operator Feedback Loop

## 1. Executive Summary & Objective

Day 24 implements the **Adaptive Policy & Operator Feedback Loop** for MemoryGuard. While Day 21 established `PolicyEngine` as the single decision authority, Day 22 established **Secure Persistence & Quarantine Isolation**, and Day 23 established **Security Audit & Incident Investigation**, Day 24 answers the core adaptive security question:

> **"How does MemoryGuard learn from security operators' post-decision evaluations without compromising the decision authority or security invariants of the PolicyEngine?"**

Day 24 provides structured telemetry collection, disagreement analysis, and deterministic calibration recommendations derived from operator feedback (`APPROVED`, `REJECTED`, `ESCALATED`).

---

## 2. Strict Security & Governance Boundary

> [!IMPORTANT]
> **Recommendation-Only Calibration Invariant**:
> Operator feedback is used **exclusively as security telemetry and calibration recommendations**. Feedback will **NEVER** directly or automatically modify `PolicyEngine` rules, score thresholds, or runtime policy decisions. The `PolicyEngine` remains the single, unyielding decision authority.

```
                    Security Decision Made by PolicyEngine
                                      │
                                      ▼
                      Active / Quarantine / Denied Store
                                      │
                                      ▼
                       Authorized Operator Inspection
                                      │
                                      ▼
                  POST /api/security/feedback (Operator Action)
                   (APPROVED / REJECTED / ESCALATED)
                                      │
         ┌────────────────────────────┴────────────────────────────┐
         │                                                         │
         ▼                                                         ▼
 Tamper-Evident Audit Log                                  OperatorFeedback Store
 (OPERATOR_FEEDBACK_SUBMITTED)                             (operator_feedback table)
         │                                                         │
         ▼                                                         ▼
 Cryptographic Hash Chain                                Feedback Telemetry Engine
                                                                   │
                                                                   ▼
                                                     Calibration Recommendation Engine
                                                        (Sample Threshold >= 10)
                                                                   │
                                                                   ▼
                                                     REST API (/api/security/feedback)
                                                     (Recommendation Guidance Only)
```

---

## 3. Supported Operator Feedback Types

When an authorized security operator reviews a decision or quarantined memory, they submit one of three standardized feedback decisions:

| Feedback Decision | Meaning | Security Telemetry Significance |
|---|---|---|
| `APPROVED` | Operator confirmed the memory is safe / benign. | If policy was `REVIEW`, flags a potential **false positive / over-blocking** pattern. |
| `REJECTED` | Operator confirmed the memory is malicious / unacceptable. | If policy was `REVIEW`, flags a potential **under-blocking / missed threat** pattern. |
| `ESCALATED` | Operator requested secondary tier / SOC L2 investigation. | Flags high uncertainty or ambiguous threat requiring policy rule review. |

---

## 4. Telemetry & Drift / Disagreement Detection

`OperatorFeedbackService` aggregates stored operator feedback into structured security telemetry:

- **Total Feedback Count**: Total number of feedback entries recorded.
- **Decision Distribution**: Counts for `APPROVED`, `REJECTED`, `ESCALATED`.
- **Review Outcomes**: `reviewApprovedCount`, `reviewRejectedCount`, `reviewEscalatedCount`.
- **Block Outcomes**: `blockEscalatedCount`.
- **Override Rate**: Ratio of policy overrides to total feedback observations.
- **Risk Level & Signal Breakdown**: Categorization of disagreements by risk level (LOW, MEDIUM, HIGH) and contributing security signals.

### Drift / Disagreement Detection Patterns:
1. **REVIEW -> APPROVED**: PolicyEngine quarantined memory, but operator verified it as benign (over-blocking).
2. **REVIEW -> REJECTED**: PolicyEngine quarantined memory, and operator confirmed it as malicious (under-blocking).
3. **BLOCK -> ESCALATED**: PolicyEngine blocked memory, but operator escalated for secondary review (potential false positive block).

---

## 5. Calibration Recommendation Engine & Thresholds

To prevent false signals from sparse data, calibration recommendations enforce a **Minimum Sample Threshold** of **10 observations**.

### Calibration States:
- **`INSUFFICIENT_DATA` (Observations < 10)**: Returns sample count and threshold status; no recommendations are generated.
- **`SUFFICIENT_DATA` (Observations >= 10)**: Evaluates telemetry patterns and generates deterministic recommendations:

| Pattern Detected | Condition | Suggested Direction | Explanation & Action |
|---|---|---|---|
| `HIGH_REVIEW_APPROVAL_RATE` | Review approval rate >= 40% | `RAISE_REVIEW_THRESHOLD` | Suggests raising REVIEW threshold or reducing rule sensitivity to minimize false positive quarantines. |
| `HIGH_REVIEW_REJECTION_RATE` | Review rejection rate >= 40% | `LOWER_REVIEW_THRESHOLD` | Suggests lowering REVIEW threshold to catch malicious memories earlier. |
| `FREQUENT_BLOCK_ESCALATION` | Block escalations >= 2 | `REVIEW_BLOCK_RULES` | Suggests auditing BLOCK policy rules to prevent unnecessary blocking of legitimate memories. |
| `BALANCED_OPERATOR_ALIGNMENT` | No threshold breached | `MAINTAIN_CURRENT_POLICY` | Confirms PolicyEngine rules align with operator expectations. |

---

## 6. REST API Control Plane

All `/api/security/feedback/**` endpoints enforce the **Day 23 Operator Authorization Boundary** via the `X-Operator-Id` header. Requests lacking a valid operator ID or passing `ANONYMOUS` are rejected with **HTTP 403 Forbidden**.

### Endpoints:
- `POST /api/security/feedback`: Submit feedback record. Returns HTTP 201 Created.
- `GET /api/security/feedback/{memoryId}`: Get feedback records for a memory ID. Returns HTTP 200 OK or 404 Not Found.
- `GET /api/security/feedback/telemetry`: Get aggregated telemetry statistics. Returns HTTP 200 OK.
- `GET /api/security/feedback/calibration`: Get calibration recommendations. Returns HTTP 200 OK.

---

## 7. Security Invariants Enforced

1. **PolicyEngine Decision Authority**: The `PolicyEngine` remains the single, authoritative decision maker. Operator feedback cannot directly or automatically mutate policies, thresholds, or decisions.
2. **Operator Authorization Boundary**: All feedback actions require valid operator credentials (`X-Operator-Id`). `ANONYMOUS` operator identity is strictly rejected.
3. **Audit Trail Integrity**: Submitting feedback emits `OPERATOR_FEEDBACK_SUBMITTED` audit events into `SecurityAuditService`, preserving SHA-256 cryptographic hash chain integrity.
4. **Zero-Plaintext Denial Protection**: Denied memory records and audit logs retain zero sensitive plaintext content.
5. **Deterministic Minimum Sample Threshold**: Calibration guidance requires at least 10 observations before emitting pattern recommendations.

---

## 8. Verification & Test Results

The full MemoryGuard test suite was executed cleanly with zero failures or errors:

- **Previous Test Count (Day 23)**: 237 tests
- **New Tests Added (Day 24)**: 27 tests (`OperatorFeedbackTests`)
- **Total Test Count**: 264 tests
- **Failures / Errors / Skipped**: 0

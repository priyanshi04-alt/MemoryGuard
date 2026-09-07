# Day 21 — Context-Aware Policy Engine

## 1. Executive Summary & Policy Engine Responsibility

On Day 21, MemoryGuard strengthened its **Policy Engine** into a security-aware, context-aware decision layer.

The core responsibility of the Policy Engine is to answer the fundamental question:
> **"Should this memory be trusted enough to enter or remain in an AI agent's memory?"**

### Policy vs. Detection Distinction
- **Detectors & Analyzers (Upstream)**: Responsible for identifying potential threats, evaluating provenance, extracting security signals, and calculating dimensional risk scores and confidence levels.
- **Policy Engine (Final Authority)**: Responsible ONLY for interpreting security evidence and making the final security decision (`ALLOW`, `REVIEW`, `BLOCK`) according to explicit, configurable rules. The Policy Engine does **NOT** perform threat detection itself.

---

## 2. Architecture & Pipeline Placement

```
Memory Gateway
    ↓
Provenance & Context Analysis
    ↓
Security Signal Extraction
    ↓
Semantic Security Analysis
    ↓
Risk Aggregation
    ↓
POLICY ENGINE  ← (DAY 21 FOCUS)
    ↓
ALLOW / REVIEW / BLOCK
    ↓
Secure Persistence (PERMITTED / QUARANTINED / DENIED)
    ↓
Audit & Observability
```

---

## 3. Policy Evaluation Precedence Order

To avoid contradictory outcomes, the Policy Engine enforces strict, deterministic priority rules (evaluated in order, first match wins):

1. **Rule 1 (`FAIL_SAFE_MISSING_ANALYSIS`)**: Missing, null, or unperformed analysis -> Safe Fallback (`REVIEW` / `QUARANTINED`).
2. **Rule 2 (`CRITICAL_HIGH_CONFIDENCE_THREAT`)**: High-impact critical threat (`SECRET_EXFILTRATION`, `PROMPT_INJECTION`, `PRIVILEGE_ESCALATION`, `TOOL_MANIPULATION`, `MALICIOUS_PERSISTENCE`, `INSTRUCTION_OVERRIDE`, `CREDENTIAL_EXPOSURE`) with risk score >= `blockThreshold` (80) AND confidence >= `highConfidenceThreshold` (0.70) -> `BLOCK` (`DENIED`).
3. **Rule 3 (`AMBIGUOUS_HIGH_RISK`)**: Risk score >= `blockThreshold` (80) BUT confidence < `highConfidenceThreshold` (0.70) -> `REVIEW` (`QUARANTINED`).
4. **Rule 4 (`BENIGN_EDUCATIONAL_CONTENT`)**: Educational prompt injection or security discussion (`BENIGN_SECURITY_CONTENT`), risk score < 50, and no high-impact malicious signals -> `ALLOW` (`PERMITTED`).
5. **Rule 5 (`BEHAVIORAL_MANIPULATION_REVIEW` / `BLOCK`)**: Content attempting to alter future behavior (`MALICIOUS_PERSISTENCE`, `INSTRUCTION_OVERRIDE`, `SUSPICIOUS_INSTRUCTION`, `SOCIAL_ENGINEERING`, `CONTEXT_MANIPULATION`) with risk score >= 50 -> `REVIEW` (`QUARANTINED`) or `BLOCK` (`DENIED`).
6. **Rule 6 (`SCORE_THRESHOLD_BLOCK`)**: Overall risk score >= `blockThreshold` (80) with high confidence -> `BLOCK` (`DENIED`).
7. **Rule 7 (`SCORE_THRESHOLD_REVIEW`)**: Overall risk score >= `reviewThreshold` (50) -> `REVIEW` (`QUARANTINED`).
8. **Rule 8 (`LOW_RISK_BASELINE`)**: Low risk content (< 50) with verified trust baseline -> `ALLOW` (`PERMITTED`).

---

## 4. Risk vs. Confidence Handling

Day 21 preserves and enforces the key principle: **Risk ≠ Certainty**.

| Risk Score | Confidence Level | Policy Rule Applied | Final Decision | Persistence Status |
|------------|------------------|---------------------|----------------|--------------------|
| HIGH (>=80)| HIGH (>=0.70)    | `CRITICAL_HIGH_CONFIDENCE_THREAT` / `SCORE_THRESHOLD_BLOCK` | **BLOCK** | `DENIED` |
| HIGH (>=80)| LOW (<0.70)      | `AMBIGUOUS_HIGH_RISK` | **REVIEW** | `QUARANTINED` |
| MEDIUM (50-79) | HIGH / LOW   | `BEHAVIORAL_MANIPULATION_REVIEW` / `SCORE_THRESHOLD_REVIEW` | **REVIEW** | `QUARANTINED` |
| LOW (<50)  | HIGH             | `LOW_RISK_BASELINE` / `BENIGN_EDUCATIONAL_CONTENT` | **ALLOW** | `PERMITTED` |

---

## 5. High-Impact Security Signals

The Policy Engine interprets granular high-impact security signals detected upstream:
- `PROMPT_INJECTION`: Indirect instruction override embedded in memory content.
- `INSTRUCTION_OVERRIDE`: Attempt to supersede system or developer prompt rules.
- `PRIVILEGE_ESCALATION`: Pretexting intent to acquire superadmin/elevated permissions.
- `TOOL_MANIPULATION`: Attempting to hijack agent function calls.
- `SECRET_EXFILTRATION`: Attempting to leak environment secrets, API keys, or passwords.
- `MALICIOUS_PERSISTENCE`: Instruction to persistently corrupt future agent memory state.
- `SOCIAL_ENGINEERING`: Pretexting or impersonation targeting agent trust.
- `CONTEXT_MANIPULATION`: Corrupting conversation or session state context.
- `SUSPICIOUS_INSTRUCTION`: Untrusted directives in memory payload.
- `BENIGN_SECURITY_CONTENT`: Non-actionable, educational references to security concepts.

---

## 6. Safe Failure Behavior & Persistence Mapping

- **Missing Evidence / Analyzer Failure**: If semantic analysis is missing, unperformed, or failed, the Policy Engine fails safely to `REVIEW` with `FAIL_SAFE_MISSING_ANALYSIS` rather than allowing uninspected memory.
- **Persistence Mapping**:
  - `ALLOW` decision -> Persistence Status: **PERMITTED** (stored as `SAFE`)
  - `REVIEW` decision -> Persistence Status: **QUARANTINED** (stored as `REVIEW` for human/agent audit)
  - `BLOCK` decision -> Persistence Status: **DENIED** (memory rejected and blocked from persistence)

---

## 7. Explainable Policy Decisions

Every policy decision generates a transparent `PolicyDecisionResult` containing:
- `decision`: `ALLOW`, `REVIEW`, `BLOCK`
- `riskScore`: int (0 - 100)
- `riskLevel`: `"HIGH"`, `"MEDIUM"`, `"LOW"`
- `confidence`: double (0.00 - 1.00)
- `policyRule`: Name of triggered rule (e.g., `AMBIGUOUS_HIGH_RISK`)
- `explanation`: Human-understandable rationale
- `contributingFactors`: List of underlying security signals
- `persistenceStatus`: `"PERMITTED"`, `"QUARANTINED"`, `"DENIED"`

---

## 8. Test Execution & Verification Results

All 189 tests across the entire project test suite passed cleanly with 0 failures:

```
[INFO] Results:
[INFO] Tests run: 189, Failures: 0, Errors: 0, Skipped: 0
[INFO] BUILD SUCCESS
```

Key test scenarios verified in `PolicyEngineTests`:
- **Scenario A**: LOW risk + HIGH confidence -> ALLOW
- **Scenario B**: HIGH risk + HIGH confidence -> BLOCK
- **Scenario C**: HIGH risk + LOW confidence -> REVIEW (Risk ≠ Certainty)
- **Scenario D**: MEDIUM suspicious instruction -> REVIEW
- **Scenario E**: Educational prompt injection discussion -> ALLOW
- **Scenario F**: Secret exfiltration attempt -> BLOCK
- **Scenario G**: Privilege escalation attempt -> BLOCK
- **Scenario H**: Tool manipulation attempt -> BLOCK
- **Scenario I**: Conflicting evidence -> Deterministic outcome
- **Scenario J**: Missing semantic analysis -> Safe fallback (REVIEW)
- **Scenario K**: Upstream analyzer failure -> Safe fallback (REVIEW)
- **Scenario L**: Empty/invalid memory assessment -> Handled safely
- **Scenario M**: Multi-layer evidence (provenance + context + semantic) -> Correct decision
- **Scenario N**: Policy Engine verified as sole authority for final ALLOW / REVIEW / BLOCK decision.

---

## 9. Architectural Significance

Day 21 completes the core security decision authority in MemoryGuard. The system now enforces multi-layer context-aware security policies with clear risk/confidence separation, deterministic evaluation precedence, transparent explainability, and safe failure defaults.

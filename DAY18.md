# Day 18 — Memory Provenance and Context Analysis Foundation

## 🎯 Day 18 Goal

The goal for Day 18 was to build the **first dedicated security-analysis layer after the Memory Gateway**:
> **"Where did this memory come from, and under what context should it be trusted?"**

In AI-agent memory security, a memory item should not be treated as equally trustworthy merely because it passed basic input validation. MemoryGuard establishes a clean, type-safe, and deterministic architectural foundation for **provenance-aware security analysis**.

---

## 🧠 What Was Implemented

### 1. Explicit Provenance Representation (`ProvenanceType`)

Created `ProvenanceType` enum (`memoryguard_backend.entity.ProvenanceType`) to replace arbitrary strings with type-safe security classifications:
* **`SYSTEM`**: System prompts, administrative setup, verified configurations. (Highest initial trust baseline)
* **`USER`**: Direct human user input (conversations, user-defined preferences). (Standard low-risk baseline)
* **`AGENT`**: Agent autonomous internal thoughts, self-reflection, planning scratchpad. (Moderate baseline)
* **`TOOL`**: External tool/function executions, external APIs, code execution results. (Requires contextual verification)
* **`RETRIEVED`**: External knowledge retrieval, RAG documents, web scraping results. (Elevated concern for indirect prompt injection)
* **`UNKNOWN`**: Unspecified, missing, or unverified provenance origin. (Elevated concern; policy review required)

Includes defensive parsing via `ProvenanceType.fromString(String)` to safely normalize incoming input and default unrecognized strings to `UNKNOWN`.

### 2. Provenance Field in Memory Entity

Updated `Memory.java`:
* Added `@Enumerated(EnumType.STRING) @Column(nullable = false) private ProvenanceType provenance = ProvenanceType.USER;`
* Added getters, setters, string overload helpers, and `@PrePersist` defaulting.
* Added `provenance` audit logging to `SecurityLog.java`.

### 3. Dedicated Provenance Analyzer (`ProvenanceAnalyzer`)

Created `ProvenanceAnalyzer` (`memoryguard_backend.security.ProvenanceAnalyzer`) as a Spring `@Component` to keep `MemoryService` thin and adhere to the Single Responsibility Principle:
* **`SYSTEM`** $\to$ Risk Score: **5** | Level: **LOW** | Category: `PROVENANCE_SYSTEM_TRUSTED` | Confidence: `1.0`
* **`USER`** $\to$ Risk Score: **10** | Level: **LOW** | Category: `PROVENANCE_USER_INPUT` | Confidence: `1.0`
* **`AGENT`** $\to$ Risk Score: **25** | Level: **LOW** | Category: `PROVENANCE_AGENT_GENERATED` | Confidence: `0.95`
* **`TOOL`** $\to$ Risk Score: **45** | Level: **LOW** | Category: `PROVENANCE_TOOL_OUTPUT` | Confidence: `0.90`
* **`RETRIEVED`** $\to$ Risk Score: **55** | Level: **MEDIUM** | Category: `PROVENANCE_RETRIEVED_EXTERNAL` | Confidence: `0.85` (triggers REVIEW)
* **`UNKNOWN`** $\to$ Risk Score: **65** | Level: **MEDIUM** | Category: `PROVENANCE_UNKNOWN_SOURCE` | Confidence: `0.75` (triggers REVIEW)

Produces structured `ProvenanceAnalysisResult` extending `SecurityAnalysisResult`.

### 4. Integration into Memory Creation Flow

The updated pipeline guarantees:
```text
Incoming Memory Payload
       ↓
[ 0. Memory Gateway Validation ] ──(Invalid)──► Reject with IllegalArgumentException
       ↓ (Valid)
[ 1. Correlation ID Generation (UUID) ]
       ↓
[ 2. Integrity Hash Calculation (SHA-256) ]
       ↓
[ 3. Provenance Analysis (ProvenanceAnalyzer) ]
       ↓ (Evaluates origin: USER / SYSTEM / AGENT / TOOL / RETRIEVED / UNKNOWN)
[ 4. Parallel Security Analyzers & AI Semantic Evaluation ]
       ↓ (MemoryRiskAnalyzer, AISemanticSecurityAnalyzer)
[ 5. Risk Aggregation (RiskAggregator) ]
       ↓ (Combines provenance risk signal with content & semantic signals)
[ 6. Policy Engine Decision (PolicyEngine: ALLOW / REVIEW / BLOCK) ]
       ↓
[ 7. Security Audit Logging & Persistence ]
```

---

## 🧪 Automated Testing

Added comprehensive unit and integration test coverage:

1. **`ProvenanceAnalyzerTests.java`** (10 test cases):
   * Tests each provenance category (`SYSTEM`, `USER`, `AGENT`, `TOOL`, `RETRIEVED`, `UNKNOWN`).
   * Tests `null` memory and `null` provenance defaulting to `UNKNOWN`.
   * Tests defensive `fromString` string parsing and case-insensitivity.
   * Tests structured metadata (risk score, risk level, category, reason, confidence, analyzer type).

2. **`MemoryGatewayFlowTests.java`** (19 test cases, including 6 new provenance pipeline tests):
   * `testProvenancePipeline_RetrievedMemory_TriggersReviewStatus`: Verifies `RETRIEVED` origin triggers `REVIEW` policy status (score 55).
   * `testProvenancePipeline_UnknownMemory_TriggersReviewStatus`: Verifies unverified `UNKNOWN` origin triggers `REVIEW` policy status (score 65).
   * `testProvenancePipeline_ToolMemory_SafeContent_Allowed`: Verifies `TOOL` memory with safe content is `ALLOWED`.
   * `testProvenancePipeline_SystemMemory_SafeContent_Allowed`: Verifies `SYSTEM` memory is `ALLOWED`.
   * `testProvenancePipeline_AgentMemory_SafeContent_Allowed`: Verifies `AGENT` memory is `ALLOWED`.
   * `testProvenancePipeline_RetrievedMemory_PromptInjection_Blocked`: Verifies high-risk content on `RETRIEVED` memory is strictly `BLOCKED` (score 85).
   * Verifies provenance is persisted into security audit logs.
   * Verifies all Day 17 Gateway boundary tests still pass.

### Test Results

```text
Results:
Tests run: 95, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

---

## 🚀 Architectural Quality Summary

* **Single Responsibility**: `ProvenanceAnalyzer` owns provenance risk evaluation; `MemoryRiskAnalyzer` owns content rules; `AISemanticSecurityAnalyzer` owns AI semantic evaluation; `MemoryService` orchestrates.
* **Extensibility**: Future analyzers (`ContextAnalyzer`, `RuleEngine`, `SemanticAnalyzer`) plug in seamlessly without rewriting `MemoryService`.
* **Backward Compatibility**: All existing constructors and tests remain 100% functional.

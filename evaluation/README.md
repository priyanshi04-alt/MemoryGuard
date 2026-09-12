# 🛡️ MemoryGuard — Security Evaluation & Validation Framework

## Overview

The **MemoryGuard Security Evaluation Framework** is a reusable evaluation module designed to validate whether the end-to-end MemoryGuard security pipeline (`Gateway` → `Provenance Analysis` → `Content Detectors` → `Semantic Analysis` → `Risk Aggregation` → `Policy Engine` → `Security Decision & Audit`) accurately detects, classifies, and handles diverse classes of safe, suspicious, manipulated, and malicious memories.

---

## Architecture & Principles

> **Non-Intrusive & Realistic**: The evaluation framework sends test memory samples through the **REAL** MemoryGuard security pipeline, capturing actual detector signals, risk scores, policy decisions, and latency metrics without modifying production security logic or using fake AI fallbacks.

```text
                               ┌───────────────────────────┐
                               │  Security Dataset (40 TC) │
                               └─────────────┬─────────────┘
                                             │
                                             ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          REAL MemoryGuard Security Pipeline                            │
│                                                                                        │
│ Memory Gateway                                                                         │
│       ↓                                                                                │
│ Provenance & Context Analysis (USER_INPUT, RETRIEVED, EXTERNAL_TOOL, SYSTEM)            │
│       ↓                                                                                │
│ Content Security Detectors (PromptInjection, Credential, PolicyOverride, SystemPrompt) │
│       ↓                                                                                │
│ AI & Baseline Semantic Security Analyzers                                              │
│       ↓                                                                                │
│ Memory Risk Aggregator (0--100 Risk Score)                                             │
│       ↓                                                                                │
│ Context-Aware Policy Engine (ALLOW / REVIEW / BLOCK)                                   │
│       ↓                                                                                │
│ Decision Explanation & Persistence (SAFE / QUARANTINED / DENIED Tombstone)              │
└────────────────────────────────────────────┬───────────────────────────────────────────┘
                                             │ (Captures actual pipeline output)
                                             ▼
                               ┌───────────────────────────┐
                               │  Metrics & Reports Engine │
                               │ - Accuracy, Precision, F1 │
                               │ - Category Performance    │
                               │ - FP / FN / Ambiguities   │
                               │ - Provenance Contrast     │
                               │ - Adversarial Testing     │
                               └───────────────────────────┘
```

---

## 10 Threat Categories Covered

1. **TRUSTED**: Normal user preferences, benign technical notes, standard scratchpad entries.
2. **SUSPICIOUS**: Unusual phrasing, queries mentioning security concepts without malicious intent.
3. **PROMPT_INJECTION**: Direct instruction overrides, developer mode bypasses, system prompt extraction attempts, character-spaced obfuscations.
4. **DATA_POISONING**: False fact injections, identity attribute tampering, behavior modification instructions.
5. **PRIVILEGE_MANIPULATION**: Unauthorized root privilege commands, role spoofing, quarantine control bypass attempts.
6. **CREDENTIAL_SECRET_LEAK**: Raw AWS keys, database passwords, active JWT bearer tokens.
7. **PII_EXPOSURE**: SSNs, credit card numbers, confidential health and salary records.
8. **CONTEXT_MANIPULATION**: Session auth state hijacking, fake emergency mode flags.
9. **CROSS_AGENT_TRUST_ABUSE**: Spoofed inter-agent trust signals, untrusted federation peer memory pollution.
10. **SAFE_BUT_AMBIGUOUS**: Educational articles on cybersecurity, defensive documentation, academic papers.

---

## Security Metrics & Analysis

The framework calculates:

- **Accuracy**: Overall proportion of correctly decided scenarios.
- **Precision**: Proportion of flagged/blocked memories that were genuinely malicious.
- **Recall**: Proportion of malicious memories correctly detected and blocked/quarantined.
- **F1 Score**: Harmonic mean of Precision and Recall.
- **False Positive Rate (FPR)**: Proportion of trusted memories incorrectly flagged/blocked.
- **False Negative Rate (FNR)**: Proportion of malicious memories incorrectly allowed into agent memory (**Must be 0%**).
- **Category Performance**: Breakdown of accuracy, precision, recall, and F1 score for each threat category.
- **Provenance Contrast Analysis**: Comparison of identical/similar payloads with trusted (`USER_INPUT`) vs untrusted (`RETRIEVED`, `EXTERNAL_TOOL`) sources.
- **Adversarial Robustness**: Testing perturbed payloads using polite framing, character spacing, and context embedding.

---

## Running the Evaluation

### Option 1: Python CLI Runner (Recommended)

From the project root:

```bash
python -m evaluation
```

Or run directly:

```bash
python evaluation/run_evaluation.py
```

### Option 2: Java Automated Tests

```bash
./mvnw test -Dtest=SecurityEvaluationFrameworkTests
```

### Option 3: REST API Endpoint

Start the Spring Boot backend server (`./mvnw spring-boot:run`), then run:

```bash
curl -X POST http://localhost:8081/api/security/evaluation/run
```

---

## Evaluation Output Location

Machine-readable JSON reports are generated at:

`evaluation/reports/latest_evaluation.json`

package memoryguard_backend.security.explainability;

/**
 * Structured security threat categories for MemoryGuard decision explainability.
 * Threat categories are derived from multi-layer security evidence, analyzer findings,
 * risk signals, and provenance context without relying on simplistic keyword matching.
 */
public enum ThreatCategory {
    PROMPT_INJECTION,
    DATA_POISONING,
    SENSITIVE_DATA,
    PROVENANCE_ANOMALY,
    TRUST_VIOLATION,
    MANIPULATION,
    POLICY_VIOLATION,
    UNKNOWN
}

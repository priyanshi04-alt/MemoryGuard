package memoryguard_backend.entity;

/**
 * Represents the origin/source of a memory item entering MemoryGuard.
 * Used by the security layer to establish a baseline trust profile.
 */
public enum ProvenanceType {

    /**
     * Direct human user input (conversations, user-defined preferences).
     * Trusted baseline for typical assistant interactions.
     */
    USER,

    /**
     * System prompts, administrative setup, verified configurations.
     * Highest initial trust baseline.
     */
    SYSTEM,

    /**
     * Agent internal thoughts, self-reflection, planning scratchpad.
     * Intermediate trust baseline.
     */
    AGENT,

    /**
     * External tool/function call outputs, API responses, code execution results.
     * Potential vector for indirect prompt injection; requires contextual verification.
     */
    TOOL,

    /**
     * External knowledge retrieval, RAG documents, web scraping results.
     * Untrusted external source; elevated risk profile.
     */
    RETRIEVED,

    /**
     * Unspecified, missing, or unverified provenance origin.
     * Elevated concern; requires review.
     */
    UNKNOWN;

    /**
     * Safely parse a string into a ProvenanceType, falling back to UNKNOWN
     * if the string is null, empty, or unrecognized.
     *
     * @param value raw provenance string
     * @return normalized ProvenanceType
     */
    public static ProvenanceType fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            return UNKNOWN;
        }
        try {
            return ProvenanceType.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return UNKNOWN;
        }
    }
}

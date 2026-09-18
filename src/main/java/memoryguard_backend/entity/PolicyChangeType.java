package memoryguard_backend.entity;

/**
 * Supported Policy Change Types for Governance Proposals.
 */
public enum PolicyChangeType {
    RAISE_REVIEW_THRESHOLD,
    LOWER_REVIEW_THRESHOLD,
    REVIEW_BLOCK_RULES,
    MAINTAIN_CURRENT_POLICY;

    /**
     * Safely parses String to PolicyChangeType or throws IllegalArgumentException.
     */
    public static PolicyChangeType fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Change type cannot be null or empty");
        }
        try {
            return PolicyChangeType.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown PolicyChangeType: '" + value + "'");
        }
    }
}

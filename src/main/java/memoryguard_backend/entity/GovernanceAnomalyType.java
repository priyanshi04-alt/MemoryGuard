package memoryguard_backend.entity;

/**
 * Supported Governance Anomaly Pattern Types.
 */
public enum GovernanceAnomalyType {
    RAPID_GOVERNANCE_ACTIVITY,
    RAPID_POLICY_ACTIVATION,
    REPEATED_REJECTION_PATTERN,
    REPEATED_APPROVAL_PATTERN,
    UNAUTHORIZED_GOVERNANCE_ATTEMPTS,
    POLICY_FLAPPING;

    /**
     * Safely parses String to GovernanceAnomalyType or throws IllegalArgumentException.
     */
    public static GovernanceAnomalyType fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Anomaly type string cannot be null or empty");
        }
        try {
            return GovernanceAnomalyType.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown GovernanceAnomalyType: '" + value + "'");
        }
    }
}

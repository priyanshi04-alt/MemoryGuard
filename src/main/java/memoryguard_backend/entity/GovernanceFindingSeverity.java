package memoryguard_backend.entity;

/**
 * Severity levels for Governance Security Findings.
 */
public enum GovernanceFindingSeverity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /**
     * Safely parses String to GovernanceFindingSeverity or throws IllegalArgumentException.
     */
    public static GovernanceFindingSeverity fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Severity string cannot be null or empty");
        }
        try {
            return GovernanceFindingSeverity.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown GovernanceFindingSeverity: '" + value + "'");
        }
    }
}

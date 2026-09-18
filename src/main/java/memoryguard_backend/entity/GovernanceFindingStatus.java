package memoryguard_backend.entity;

/**
 * Supported lifecycle states for Governance Security Findings.
 */
public enum GovernanceFindingStatus {
    OPEN,
    ACKNOWLEDGED,
    RESOLVED;

    /**
     * Evaluates whether a transition from this state to the target state is allowed.
     */
    public boolean canTransitionTo(GovernanceFindingStatus targetState) {
        if (targetState == null) {
            return false;
        }

        switch (this) {
            case OPEN:
                return targetState == ACKNOWLEDGED || targetState == RESOLVED;
            case ACKNOWLEDGED:
                return targetState == RESOLVED;
            case RESOLVED:
            default:
                return false;
        }
    }

    /**
     * Validates state transition and throws IllegalStateException on invalid transition.
     */
    public void validateTransition(GovernanceFindingStatus targetState) {
        if (!canTransitionTo(targetState)) {
            throw new IllegalStateException("Invalid state transition: cannot transition finding from '" + this + "' to '" + targetState + "'.");
        }
    }

    /**
     * Safely parses String to GovernanceFindingStatus or throws IllegalArgumentException.
     */
    public static GovernanceFindingStatus fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("Finding status string cannot be null or empty");
        }
        try {
            return GovernanceFindingStatus.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown GovernanceFindingStatus: '" + value + "'");
        }
    }
}

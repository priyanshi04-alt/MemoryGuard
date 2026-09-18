package memoryguard_backend.entity;

/**
 * Supported Policy Version and Proposal Lifecycle States.
 */
public enum PolicyVersionState {
    PENDING_APPROVAL,
    APPROVED,
    REJECTED,
    ACTIVE,
    SUPERSEDED;

    /**
     * Evaluates whether a transition from this state to the target state is allowed.
     */
    public boolean canTransitionTo(PolicyVersionState targetState) {
        if (targetState == null) {
            return false;
        }

        switch (this) {
            case PENDING_APPROVAL:
                return targetState == APPROVED || targetState == REJECTED;
            case APPROVED:
                return targetState == ACTIVE;
            case ACTIVE:
                return targetState == SUPERSEDED;
            case REJECTED:
            case SUPERSEDED:
            default:
                return false;
        }
    }

    /**
     * Validates state transition and throws IllegalStateException on invalid transition.
     */
    public void validateTransition(PolicyVersionState targetState) {
        if (!canTransitionTo(targetState)) {
            throw new IllegalStateException("Invalid state transition: cannot transition from '" + this + "' to '" + targetState + "'.");
        }
    }

    /**
     * Safely parses String to PolicyVersionState or throws IllegalArgumentException.
     */
    public static PolicyVersionState fromString(String value) {
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("State string cannot be null or empty");
        }
        try {
            return PolicyVersionState.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown PolicyVersionState: '" + value + "'");
        }
    }
}

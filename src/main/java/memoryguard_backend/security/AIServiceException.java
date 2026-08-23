package memoryguard_backend.security;

public class AIServiceException extends RuntimeException {
    public enum FailureType {
        CONNECTION_FAILURE,
        TIMEOUT,
        HTTP_ERROR,
        MALFORMED_RESPONSE,
        INVALID_RESULT,
        INPUT_EXCEEDED,
        BLANK_INPUT
    }

    private final FailureType failureType;

    public AIServiceException(FailureType failureType, String message) {
        super(message);
        this.failureType = failureType;
    }

    public AIServiceException(FailureType failureType, String message, Throwable cause) {
        super(message, cause);
        this.failureType = failureType;
    }

    public FailureType getFailureType() {
        return failureType;
    }
}

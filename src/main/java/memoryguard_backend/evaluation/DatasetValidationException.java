package memoryguard_backend.evaluation;

public class DatasetValidationException extends RuntimeException {

    public DatasetValidationException(String message) {
        super(message);
    }

    public DatasetValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}

package memoryguard_backend.dto;

public class AuditIntegrityResult {

    private boolean valid;
    private int totalEvents;
    private Integer failureIndex;
    private String failureEventId;
    private String failureReason;

    public AuditIntegrityResult() {
    }

    public AuditIntegrityResult(boolean valid, int totalEvents, Integer failureIndex, String failureEventId, String failureReason) {
        this.valid = valid;
        this.totalEvents = totalEvents;
        this.failureIndex = failureIndex;
        this.failureEventId = failureEventId;
        this.failureReason = failureReason;
    }

    public static AuditIntegrityResult valid(int totalEvents) {
        return new AuditIntegrityResult(true, totalEvents, null, null, "Audit trail integrity verified successfully. Hash chain is intact.");
    }

    public static AuditIntegrityResult invalid(int totalEvents, int failureIndex, String failureEventId, String failureReason) {
        return new AuditIntegrityResult(false, totalEvents, failureIndex, failureEventId, failureReason);
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public int getTotalEvents() {
        return totalEvents;
    }

    public void setTotalEvents(int totalEvents) {
        this.totalEvents = totalEvents;
    }

    public Integer getFailureIndex() {
        return failureIndex;
    }

    public void setFailureIndex(Integer failureIndex) {
        this.failureIndex = failureIndex;
    }

    public String getFailureEventId() {
        return failureEventId;
    }

    public void setFailureEventId(String failureEventId) {
        this.failureEventId = failureEventId;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }
}

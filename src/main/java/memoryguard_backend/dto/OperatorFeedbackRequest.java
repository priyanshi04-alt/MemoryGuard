package memoryguard_backend.dto;

public class OperatorFeedbackRequest {

    private Long memoryId;
    private String correlationId;
    private String operatorId;
    private String feedbackDecision; // APPROVED, REJECTED, ESCALATED
    private String notes;

    public OperatorFeedbackRequest() {
    }

    public OperatorFeedbackRequest(Long memoryId, String correlationId, String operatorId, String feedbackDecision, String notes) {
        this.memoryId = memoryId;
        this.correlationId = correlationId;
        this.operatorId = operatorId;
        this.feedbackDecision = feedbackDecision;
        this.notes = notes;
    }

    public Long getMemoryId() {
        return memoryId;
    }

    public void setMemoryId(Long memoryId) {
        this.memoryId = memoryId;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
    }

    public String getOperatorId() {
        return operatorId;
    }

    public void setOperatorId(String operatorId) {
        this.operatorId = operatorId;
    }

    public String getFeedbackDecision() {
        return feedbackDecision;
    }

    public void setFeedbackDecision(String feedbackDecision) {
        this.feedbackDecision = feedbackDecision;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }
}

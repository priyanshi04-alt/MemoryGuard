package memoryguard_backend.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "operator_feedback")
public class OperatorFeedback {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 36)
    private String feedbackId;

    @Column(nullable = false)
    private Long memoryId;

    @Column(length = 64)
    private String correlationId;

    @Column(nullable = false)
    private String operatorId;

    @Column(nullable = false, length = 30)
    private String feedbackDecision; // APPROVED, REJECTED, ESCALATED

    private LocalDateTime timestamp;

    @Column(length = 30)
    private String policyDecision; // ALLOW, REVIEW, BLOCK

    private Integer riskScore;

    @Column(length = 30)
    private String riskLevel; // LOW, MEDIUM, HIGH

    @Column(columnDefinition = "TEXT")
    private String policyReason;

    @Column(columnDefinition = "TEXT")
    private String contributingFactors;

    @Column(columnDefinition = "TEXT")
    private String notes;

    public OperatorFeedback() {
    }

    @PrePersist
    protected void onCreate() {
        if (feedbackId == null || feedbackId.trim().isEmpty()) {
            feedbackId = UUID.randomUUID().toString();
        }
        if (timestamp == null) {
            timestamp = LocalDateTime.now();
        }
    }

    // Getters and Setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFeedbackId() {
        return feedbackId;
    }

    public void setFeedbackId(String feedbackId) {
        this.feedbackId = feedbackId;
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

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getPolicyDecision() {
        return policyDecision;
    }

    public void setPolicyDecision(String policyDecision) {
        this.policyDecision = policyDecision;
    }

    public Integer getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(Integer riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public String getPolicyReason() {
        return policyReason;
    }

    public void setPolicyReason(String policyReason) {
        this.policyReason = policyReason;
    }

    public String getContributingFactors() {
        return contributingFactors;
    }

    public void setContributingFactors(String contributingFactors) {
        this.contributingFactors = contributingFactors;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }
}

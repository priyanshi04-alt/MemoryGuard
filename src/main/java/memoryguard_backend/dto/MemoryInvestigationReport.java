package memoryguard_backend.dto;

import memoryguard_backend.entity.SecurityAuditEvent;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class MemoryInvestigationReport {

    private String correlationId;
    private Long memoryId;
    private Long quarantineId;
    private String finalState;
    private String policyDecision;
    private Integer riskScore;
    private String riskLevel;
    private String policyReason;
    private List<String> contributingFactors = new ArrayList<>();
    private List<String> analyzerContributions = new ArrayList<>();
    private Boolean isQuarantined = false;
    private Boolean isInspected = false;
    private Boolean isApprovedOrRejected = false;
    private String operatorId;
    private String cryptographicHash;
    private List<SecurityAuditEvent> timeline = new ArrayList<>();
    private LocalDateTime generatedAt;

    public MemoryInvestigationReport() {
        this.generatedAt = LocalDateTime.now();
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
    }

    public Long getMemoryId() {
        return memoryId;
    }

    public void setMemoryId(Long memoryId) {
        this.memoryId = memoryId;
    }

    public Long getQuarantineId() {
        return quarantineId;
    }

    public void setQuarantineId(Long quarantineId) {
        this.quarantineId = quarantineId;
    }

    public String getFinalState() {
        return finalState;
    }

    public void setFinalState(String finalState) {
        this.finalState = finalState;
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

    public List<String> getContributingFactors() {
        return contributingFactors;
    }

    public void setContributingFactors(List<String> contributingFactors) {
        this.contributingFactors = contributingFactors;
    }

    public List<String> getAnalyzerContributions() {
        return analyzerContributions;
    }

    public void setAnalyzerContributions(List<String> analyzerContributions) {
        this.analyzerContributions = analyzerContributions;
    }

    public Boolean getIsQuarantined() {
        return isQuarantined;
    }

    public void setIsQuarantined(Boolean isQuarantined) {
        this.isQuarantined = isQuarantined;
    }

    public Boolean getIsInspected() {
        return isInspected;
    }

    public void setIsInspected(Boolean isInspected) {
        this.isInspected = isInspected;
    }

    public Boolean getIsApprovedOrRejected() {
        return isApprovedOrRejected;
    }

    public void setIsApprovedOrRejected(Boolean isApprovedOrRejected) {
        this.isApprovedOrRejected = isApprovedOrRejected;
    }

    public String getOperatorId() {
        return operatorId;
    }

    public void setOperatorId(String operatorId) {
        this.operatorId = operatorId;
    }

    public String getCryptographicHash() {
        return cryptographicHash;
    }

    public void setCryptographicHash(String cryptographicHash) {
        this.cryptographicHash = cryptographicHash;
    }

    public List<SecurityAuditEvent> getTimeline() {
        return timeline;
    }

    public void setTimeline(List<SecurityAuditEvent> timeline) {
        this.timeline = timeline;
    }

    public LocalDateTime getGeneratedAt() {
        return generatedAt;
    }

    public void setGeneratedAt(LocalDateTime generatedAt) {
        this.generatedAt = generatedAt;
    }
}

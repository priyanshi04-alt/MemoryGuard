package memoryguard_backend.dto;

import java.util.HashMap;
import java.util.Map;

public class OperatorFeedbackTelemetry {

    private long totalFeedbackCount;
    private long approvedCount;
    private long rejectedCount;
    private long escalatedCount;

    private long reviewApprovedCount;
    private long reviewRejectedCount;
    private long reviewEscalatedCount;
    private long blockEscalatedCount;

    private double overrideRate;

    private Map<String, Long> feedbackDistribution = new HashMap<>();
    private Map<String, Long> riskLevelDisagreements = new HashMap<>();
    private Map<String, Long> signalDisagreements = new HashMap<>();

    public OperatorFeedbackTelemetry() {
    }

    public long getTotalFeedbackCount() {
        return totalFeedbackCount;
    }

    public void setTotalFeedbackCount(long totalFeedbackCount) {
        this.totalFeedbackCount = totalFeedbackCount;
    }

    public long getApprovedCount() {
        return approvedCount;
    }

    public void setApprovedCount(long approvedCount) {
        this.approvedCount = approvedCount;
    }

    public long getRejectedCount() {
        return rejectedCount;
    }

    public void setRejectedCount(long rejectedCount) {
        this.rejectedCount = rejectedCount;
    }

    public long getEscalatedCount() {
        return escalatedCount;
    }

    public void setEscalatedCount(long escalatedCount) {
        this.escalatedCount = escalatedCount;
    }

    public long getReviewApprovedCount() {
        return reviewApprovedCount;
    }

    public void setReviewApprovedCount(long reviewApprovedCount) {
        this.reviewApprovedCount = reviewApprovedCount;
    }

    public long getReviewRejectedCount() {
        return reviewRejectedCount;
    }

    public void setReviewRejectedCount(long reviewRejectedCount) {
        this.reviewRejectedCount = reviewRejectedCount;
    }

    public long getReviewEscalatedCount() {
        return reviewEscalatedCount;
    }

    public void setReviewEscalatedCount(long reviewEscalatedCount) {
        this.reviewEscalatedCount = reviewEscalatedCount;
    }

    public long getBlockEscalatedCount() {
        return blockEscalatedCount;
    }

    public void setBlockEscalatedCount(long blockEscalatedCount) {
        this.blockEscalatedCount = blockEscalatedCount;
    }

    public double getOverrideRate() {
        return overrideRate;
    }

    public void setOverrideRate(double overrideRate) {
        this.overrideRate = overrideRate;
    }

    public Map<String, Long> getFeedbackDistribution() {
        return feedbackDistribution;
    }

    public void setFeedbackDistribution(Map<String, Long> feedbackDistribution) {
        this.feedbackDistribution = feedbackDistribution;
    }

    public Map<String, Long> getRiskLevelDisagreements() {
        return riskLevelDisagreements;
    }

    public void setRiskLevelDisagreements(Map<String, Long> riskLevelDisagreements) {
        this.riskLevelDisagreements = riskLevelDisagreements;
    }

    public Map<String, Long> getSignalDisagreements() {
        return signalDisagreements;
    }

    public void setSignalDisagreements(Map<String, Long> signalDisagreements) {
        this.signalDisagreements = signalDisagreements;
    }
}

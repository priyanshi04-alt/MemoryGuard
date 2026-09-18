package memoryguard_backend.dto;

public class CreatePolicyProposalRequest {

    private String changeType;
    private String reason;
    private String evidence;
    private String recommendationId;
    private Integer proposedBlockThreshold;
    private Integer proposedReviewThreshold;

    public CreatePolicyProposalRequest() {
    }

    public CreatePolicyProposalRequest(String changeType, String reason, String evidence) {
        this.changeType = changeType;
        this.reason = reason;
        this.evidence = evidence;
    }

    public CreatePolicyProposalRequest(String changeType, String reason, String evidence, String recommendationId, Integer proposedBlockThreshold, Integer proposedReviewThreshold) {
        this.changeType = changeType;
        this.reason = reason;
        this.evidence = evidence;
        this.recommendationId = recommendationId;
        this.proposedBlockThreshold = proposedBlockThreshold;
        this.proposedReviewThreshold = proposedReviewThreshold;
    }

    public String getChangeType() {
        return changeType;
    }

    public void setChangeType(String changeType) {
        this.changeType = changeType;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getRecommendationId() {
        return recommendationId;
    }

    public void setRecommendationId(String recommendationId) {
        this.recommendationId = recommendationId;
    }

    public Integer getProposedBlockThreshold() {
        return proposedBlockThreshold;
    }

    public void setProposedBlockThreshold(Integer proposedBlockThreshold) {
        this.proposedBlockThreshold = proposedBlockThreshold;
    }

    public Integer getProposedReviewThreshold() {
        return proposedReviewThreshold;
    }

    public void setProposedReviewThreshold(Integer proposedReviewThreshold) {
        this.proposedReviewThreshold = proposedReviewThreshold;
    }
}

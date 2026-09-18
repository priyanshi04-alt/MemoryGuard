package memoryguard_backend.dto;

import memoryguard_backend.entity.PolicyChangeProposal;

import java.time.LocalDateTime;

public class PolicyProposalResponse {

    private Long id;
    private String proposalId;
    private String recommendationId;
    private Integer currentPolicyVersion;
    private Integer proposedPolicyVersion;
    private String changeType;
    private Integer currentReviewThreshold;
    private Integer proposedReviewThreshold;
    private Integer currentBlockThreshold;
    private Integer proposedBlockThreshold;
    private String justification;
    private String evidence;
    private String rejectionReason;
    private String status;
    private String proposedBy;
    private String reviewedBy;
    private LocalDateTime createdAt;
    private LocalDateTime reviewedAt;
    private LocalDateTime activatedAt;

    public PolicyProposalResponse() {
    }

    public static PolicyProposalResponse fromEntity(PolicyChangeProposal proposal) {
        if (proposal == null) {
            return null;
        }
        PolicyProposalResponse dto = new PolicyProposalResponse();
        dto.id = proposal.getId();
        dto.proposalId = proposal.getProposalId();
        dto.recommendationId = proposal.getRecommendationId();
        dto.currentPolicyVersion = proposal.getCurrentPolicyVersion();
        dto.proposedPolicyVersion = proposal.getProposedPolicyVersion();
        dto.changeType = proposal.getChangeType();
        dto.currentReviewThreshold = proposal.getCurrentReviewThreshold();
        dto.proposedReviewThreshold = proposal.getProposedReviewThreshold();
        dto.currentBlockThreshold = proposal.getCurrentBlockThreshold();
        dto.proposedBlockThreshold = proposal.getProposedBlockThreshold();
        dto.justification = proposal.getReason();
        dto.evidence = proposal.getEvidence();
        dto.rejectionReason = proposal.getRejectionReason();
        dto.status = proposal.getStatus();
        dto.proposedBy = proposal.getCreatedBy();
        dto.reviewedBy = proposal.getReviewedBy();
        dto.createdAt = proposal.getCreatedAt();
        dto.reviewedAt = proposal.getReviewedAt();
        dto.activatedAt = proposal.getActivatedAt();
        return dto;
    }

    public Long getId() { return id; }
    public String getProposalId() { return proposalId; }
    public String getRecommendationId() { return recommendationId; }
    public String getSourceRecommendationId() { return recommendationId; }
    public Integer getCurrentPolicyVersion() { return currentPolicyVersion; }
    public Integer getProposedPolicyVersion() { return proposedPolicyVersion; }
    public String getChangeType() { return changeType; }
    public Integer getCurrentReviewThreshold() { return currentReviewThreshold; }
    public Integer getProposedReviewThreshold() { return proposedReviewThreshold; }
    public Integer getCurrentBlockThreshold() { return currentBlockThreshold; }
    public Integer getProposedBlockThreshold() { return proposedBlockThreshold; }
    public String getJustification() { return justification; }
    public String getReason() { return justification; }
    public String getEvidence() { return evidence; }
    public String getRejectionReason() { return rejectionReason; }
    public String getStatus() { return status; }
    public String getProposedBy() { return proposedBy; }
    public String getCreatedBy() { return proposedBy; }
    public String getReviewedBy() { return reviewedBy; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getReviewedAt() { return reviewedAt; }
    public LocalDateTime getActivatedAt() { return activatedAt; }
}

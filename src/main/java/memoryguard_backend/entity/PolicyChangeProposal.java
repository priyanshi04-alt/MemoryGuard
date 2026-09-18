package memoryguard_backend.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "policy_change_proposal")
public class PolicyChangeProposal {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 36)
    private String proposalId;

    @Column(length = 100)
    private String recommendationId;

    private Integer currentPolicyVersion;
    private Integer proposedPolicyVersion;

    @Column(nullable = false, length = 50)
    private String changeType; // RAISE_REVIEW_THRESHOLD, LOWER_REVIEW_THRESHOLD, REVIEW_BLOCK_RULES, MAINTAIN_CURRENT_POLICY

    private Integer currentReviewThreshold;
    private Integer proposedReviewThreshold;
    private Integer currentBlockThreshold;
    private Integer proposedBlockThreshold;

    @Column(columnDefinition = "TEXT")
    private String reason;

    @Column(columnDefinition = "TEXT")
    private String evidence;

    @Column(columnDefinition = "TEXT")
    private String rejectionReason;

    @Column(nullable = false, length = 30)
    private String status; // PENDING_APPROVAL, APPROVED, REJECTED, ACTIVE

    @Column(nullable = false, length = 64)
    private String createdBy;

    @Column(length = 64)
    private String reviewedBy;

    private LocalDateTime createdAt;
    private LocalDateTime reviewedAt;
    private LocalDateTime activatedAt;

    public PolicyChangeProposal() {
    }

    @PrePersist
    protected void onCreate() {
        if (proposalId == null || proposalId.trim().isEmpty()) {
            proposalId = UUID.randomUUID().toString();
        }
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (status == null || status.trim().isEmpty()) {
            status = "PENDING_APPROVAL";
        }
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getProposalId() {
        return proposalId;
    }

    public void setProposalId(String proposalId) {
        this.proposalId = proposalId;
    }

    public String getRecommendationId() {
        return recommendationId;
    }

    public void setRecommendationId(String recommendationId) {
        this.recommendationId = recommendationId;
    }

    // Alias for recommendationId
    public String getSourceRecommendationId() {
        return recommendationId;
    }

    public void setSourceRecommendationId(String sourceRecommendationId) {
        this.recommendationId = sourceRecommendationId;
    }

    public Integer getCurrentPolicyVersion() {
        return currentPolicyVersion;
    }

    public void setCurrentPolicyVersion(Integer currentPolicyVersion) {
        this.currentPolicyVersion = currentPolicyVersion;
    }

    public Integer getProposedPolicyVersion() {
        return proposedPolicyVersion;
    }

    public void setProposedPolicyVersion(Integer proposedPolicyVersion) {
        this.proposedPolicyVersion = proposedPolicyVersion;
    }

    public String getChangeType() {
        return changeType;
    }

    public void setChangeType(String changeType) {
        this.changeType = changeType;
    }

    public Integer getCurrentReviewThreshold() {
        return currentReviewThreshold;
    }

    public void setCurrentReviewThreshold(Integer currentReviewThreshold) {
        this.currentReviewThreshold = currentReviewThreshold;
    }

    public Integer getProposedReviewThreshold() {
        return proposedReviewThreshold;
    }

    public void setProposedReviewThreshold(Integer proposedReviewThreshold) {
        this.proposedReviewThreshold = proposedReviewThreshold;
    }

    public Integer getCurrentBlockThreshold() {
        return currentBlockThreshold;
    }

    public void setCurrentBlockThreshold(Integer currentBlockThreshold) {
        this.currentBlockThreshold = currentBlockThreshold;
    }

    public Integer getProposedBlockThreshold() {
        return proposedBlockThreshold;
    }

    public void setProposedBlockThreshold(Integer proposedBlockThreshold) {
        this.proposedBlockThreshold = proposedBlockThreshold;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    // Alias for reason
    public String getJustification() {
        return reason;
    }

    public void setJustification(String justification) {
        this.reason = justification;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getRejectionReason() {
        return rejectionReason;
    }

    public void setRejectionReason(String rejectionReason) {
        this.rejectionReason = rejectionReason;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    // Alias for createdBy
    public String getProposedBy() {
        return createdBy;
    }

    public void setProposedBy(String proposedBy) {
        this.createdBy = proposedBy;
    }

    public String getReviewedBy() {
        return reviewedBy;
    }

    public void setReviewedBy(String reviewedBy) {
        this.reviewedBy = reviewedBy;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getReviewedAt() {
        return reviewedAt;
    }

    public void setReviewedAt(LocalDateTime reviewedAt) {
        this.reviewedAt = reviewedAt;
    }

    public LocalDateTime getActivatedAt() {
        return activatedAt;
    }

    public void setActivatedAt(LocalDateTime activatedAt) {
        this.activatedAt = activatedAt;
    }
}

package memoryguard_backend.dto;

import memoryguard_backend.entity.PolicyVersion;

import java.time.LocalDateTime;

public class PolicyVersionResponse {

    private Long id;
    private Integer versionNumber;
    private int reviewThreshold;
    private int blockThreshold;
    private double highConfidenceThreshold;
    private boolean criticalThreatAutoBlock;
    private String failSafeDefaultDecision;
    private String policyState;
    private String createdBy;
    private String approvedBy;
    private String activatedBy;
    private LocalDateTime createdAt;
    private LocalDateTime approvedAt;
    private LocalDateTime activatedAt;
    private LocalDateTime supersededAt;
    private String changeReason;
    private Integer parentVersionId;

    public PolicyVersionResponse() {
    }

    public static PolicyVersionResponse fromEntity(PolicyVersion entity) {
        if (entity == null) {
            return null;
        }
        PolicyVersionResponse dto = new PolicyVersionResponse();
        dto.id = entity.getId();
        dto.versionNumber = entity.getVersion();
        dto.reviewThreshold = entity.getReviewThreshold();
        dto.blockThreshold = entity.getBlockThreshold();
        dto.highConfidenceThreshold = entity.getHighConfidenceThreshold();
        dto.criticalThreatAutoBlock = entity.isCriticalThreatAutoBlock();
        dto.failSafeDefaultDecision = entity.getFailSafeDefaultDecision();
        dto.policyState = entity.getStatus();
        dto.createdBy = entity.getCreatedBy();
        dto.approvedBy = entity.getApprovedBy();
        dto.activatedBy = entity.getActivatedBy();
        dto.createdAt = entity.getCreatedAt();
        dto.approvedAt = entity.getApprovedAt();
        dto.activatedAt = entity.getActivatedAt();
        dto.supersededAt = entity.getSupersededAt();
        dto.changeReason = entity.getReason();
        dto.parentVersionId = entity.getPreviousVersion();
        return dto;
    }

    public Long getId() { return id; }
    public Integer getVersionNumber() { return versionNumber; }
    public Integer getVersion() { return versionNumber; }
    public int getReviewThreshold() { return reviewThreshold; }
    public int getBlockThreshold() { return blockThreshold; }
    public double getHighConfidenceThreshold() { return highConfidenceThreshold; }
    public boolean isCriticalThreatAutoBlock() { return criticalThreatAutoBlock; }
    public String getFailSafeDefaultDecision() { return failSafeDefaultDecision; }
    public String getPolicyState() { return policyState; }
    public String getStatus() { return policyState; }
    public String getCreatedBy() { return createdBy; }
    public String getApprovedBy() { return approvedBy; }
    public String getActivatedBy() { return activatedBy; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public LocalDateTime getApprovedAt() { return approvedAt; }
    public LocalDateTime getActivatedAt() { return activatedAt; }
    public LocalDateTime getSupersededAt() { return supersededAt; }
    public String getChangeReason() { return changeReason; }
    public String getReason() { return changeReason; }
    public Integer getParentVersionId() { return parentVersionId; }
    public Integer getPreviousVersion() { return parentVersionId; }
}

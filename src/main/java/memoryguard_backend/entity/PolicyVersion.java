package memoryguard_backend.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "policy_version")
public class PolicyVersion {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Integer version;

    @Column(nullable = false, length = 30)
    private String status; // PENDING_APPROVAL, APPROVED, REJECTED, ACTIVE, SUPERSEDED

    @Column(length = 64)
    private String createdBy;

    @Column(length = 64)
    private String approvedBy;

    @Column(length = 64)
    private String activatedBy;

    private LocalDateTime createdAt;
    private LocalDateTime approvedAt;
    private LocalDateTime activatedAt;
    private LocalDateTime supersededAt;

    @Column(columnDefinition = "TEXT")
    private String reason;

    private Integer previousVersion;

    private int blockThreshold = 80;
    private int reviewThreshold = 50;
    private double highConfidenceThreshold = 0.70;
    private boolean criticalThreatAutoBlock = true;

    @Column(length = 30)
    private String failSafeDefaultDecision = "REVIEW";

    public PolicyVersion() {
    }

    public PolicyVersion(Integer version, String status, String createdBy, String reason, Integer previousVersion,
                         int blockThreshold, int reviewThreshold, double highConfidenceThreshold,
                         boolean criticalThreatAutoBlock, String failSafeDefaultDecision) {
        this.version = version;
        this.status = status;
        this.createdBy = createdBy;
        this.reason = reason;
        this.previousVersion = previousVersion;
        this.blockThreshold = blockThreshold;
        this.reviewThreshold = reviewThreshold;
        this.highConfidenceThreshold = highConfidenceThreshold;
        this.criticalThreatAutoBlock = criticalThreatAutoBlock;
        this.failSafeDefaultDecision = failSafeDefaultDecision;
    }

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    // Alias for getVersion()
    public Integer getVersionNumber() {
        return version;
    }

    public void setVersionNumber(Integer versionNumber) {
        this.version = versionNumber;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    // Alias for getStatus()
    public String getPolicyState() {
        return status;
    }

    public void setPolicyState(String policyState) {
        this.status = policyState;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public String getApprovedBy() {
        return approvedBy;
    }

    public void setApprovedBy(String approvedBy) {
        this.approvedBy = approvedBy;
    }

    public String getActivatedBy() {
        return activatedBy;
    }

    public void setActivatedBy(String activatedBy) {
        this.activatedBy = activatedBy;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getApprovedAt() {
        return approvedAt;
    }

    public void setApprovedAt(LocalDateTime approvedAt) {
        this.approvedAt = approvedAt;
    }

    public LocalDateTime getActivatedAt() {
        return activatedAt;
    }

    public void setActivatedAt(LocalDateTime activatedAt) {
        this.activatedAt = activatedAt;
    }

    public LocalDateTime getSupersededAt() {
        return supersededAt;
    }

    public void setSupersededAt(LocalDateTime supersededAt) {
        this.supersededAt = supersededAt;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    // Alias for getReason()
    public String getChangeReason() {
        return reason;
    }

    public void setChangeReason(String changeReason) {
        this.reason = changeReason;
    }

    public Integer getPreviousVersion() {
        return previousVersion;
    }

    public void setPreviousVersion(Integer previousVersion) {
        this.previousVersion = previousVersion;
    }

    // Alias for getPreviousVersion()
    public Integer getParentVersionId() {
        return previousVersion;
    }

    public void setParentVersionId(Integer parentVersionId) {
        this.previousVersion = parentVersionId;
    }

    public int getBlockThreshold() {
        return blockThreshold;
    }

    public void setBlockThreshold(int blockThreshold) {
        this.blockThreshold = blockThreshold;
    }

    public int getReviewThreshold() {
        return reviewThreshold;
    }

    public void setReviewThreshold(int reviewThreshold) {
        this.reviewThreshold = reviewThreshold;
    }

    public double getHighConfidenceThreshold() {
        return highConfidenceThreshold;
    }

    public void setHighConfidenceThreshold(double highConfidenceThreshold) {
        this.highConfidenceThreshold = highConfidenceThreshold;
    }

    public boolean isCriticalThreatAutoBlock() {
        return criticalThreatAutoBlock;
    }

    public void setCriticalThreatAutoBlock(boolean criticalThreatAutoBlock) {
        this.criticalThreatAutoBlock = criticalThreatAutoBlock;
    }

    public String getFailSafeDefaultDecision() {
        return failSafeDefaultDecision;
    }

    public void setFailSafeDefaultDecision(String failSafeDefaultDecision) {
        this.failSafeDefaultDecision = failSafeDefaultDecision;
    }
}

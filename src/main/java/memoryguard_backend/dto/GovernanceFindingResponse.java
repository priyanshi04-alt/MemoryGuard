package memoryguard_backend.dto;

import memoryguard_backend.entity.GovernanceSecurityFinding;

import java.time.LocalDateTime;

public class GovernanceFindingResponse {

    private Long id;
    private String findingId;
    private String anomalyType;
    private String severity;
    private String operatorId;
    private String description;
    private String evidence;
    private String status;
    private LocalDateTime detectedAt;
    private String acknowledgedBy;
    private LocalDateTime acknowledgedAt;
    private String resolvedBy;
    private LocalDateTime resolvedAt;
    private String resolutionNotes;

    public GovernanceFindingResponse() {
    }

    public static GovernanceFindingResponse fromEntity(GovernanceSecurityFinding entity) {
        if (entity == null) {
            return null;
        }
        GovernanceFindingResponse dto = new GovernanceFindingResponse();
        dto.id = entity.getId();
        dto.findingId = entity.getFindingId();
        dto.anomalyType = entity.getAnomalyType();
        dto.severity = entity.getSeverity();
        dto.operatorId = entity.getOperatorId();
        dto.description = entity.getDescription();
        dto.evidence = entity.getEvidence();
        dto.status = entity.getStatus();
        dto.detectedAt = entity.getDetectedAt();
        dto.acknowledgedBy = entity.getAcknowledgedBy();
        dto.acknowledgedAt = entity.getAcknowledgedAt();
        dto.resolvedBy = entity.getResolvedBy();
        dto.resolvedAt = entity.getResolvedAt();
        dto.resolutionNotes = entity.getResolutionNotes();
        return dto;
    }

    public Long getId() { return id; }
    public String getFindingId() { return findingId; }
    public String getAnomalyType() { return anomalyType; }
    public String getSeverity() { return severity; }
    public String getOperatorId() { return operatorId; }
    public String getDescription() { return description; }
    public String getEvidence() { return evidence; }
    public String getStatus() { return status; }
    public LocalDateTime getDetectedAt() { return detectedAt; }
    public String getAcknowledgedBy() { return acknowledgedBy; }
    public LocalDateTime getAcknowledgedAt() { return acknowledgedAt; }
    public String getResolvedBy() { return resolvedBy; }
    public LocalDateTime getResolvedAt() { return resolvedAt; }
    public String getResolutionNotes() { return resolutionNotes; }
}

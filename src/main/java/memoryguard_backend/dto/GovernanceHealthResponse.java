package memoryguard_backend.dto;

public class GovernanceHealthResponse {

    private boolean activePolicyPresent;
    private long activePolicyCount;
    private long pendingProposalCount;
    private long approvedNotActivatedProposalCount;
    private long rejectedProposalCount;
    private boolean governanceAuditAvailable;
    private boolean auditChainIntegrityValid;
    private String status;
    private String message;

    public GovernanceHealthResponse() {
    }

    public GovernanceHealthResponse(
            boolean activePolicyPresent,
            long activePolicyCount,
            long pendingProposalCount,
            long approvedNotActivatedProposalCount,
            long rejectedProposalCount,
            boolean governanceAuditAvailable,
            boolean auditChainIntegrityValid,
            String status,
            String message) {
        this.activePolicyPresent = activePolicyPresent;
        this.activePolicyCount = activePolicyCount;
        this.pendingProposalCount = pendingProposalCount;
        this.approvedNotActivatedProposalCount = approvedNotActivatedProposalCount;
        this.rejectedProposalCount = rejectedProposalCount;
        this.governanceAuditAvailable = governanceAuditAvailable;
        this.auditChainIntegrityValid = auditChainIntegrityValid;
        this.status = status;
        this.message = message;
    }

    public boolean isActivePolicyPresent() { return activePolicyPresent; }
    public void setActivePolicyPresent(boolean activePolicyPresent) { this.activePolicyPresent = activePolicyPresent; }

    public long getActivePolicyCount() { return activePolicyCount; }
    public void setActivePolicyCount(long activePolicyCount) { this.activePolicyCount = activePolicyCount; }

    public long getPendingProposalCount() { return pendingProposalCount; }
    public void setPendingProposalCount(long pendingProposalCount) { this.pendingProposalCount = pendingProposalCount; }

    public long getApprovedNotActivatedProposalCount() { return approvedNotActivatedProposalCount; }
    public void setApprovedNotActivatedProposalCount(long approvedNotActivatedProposalCount) { this.approvedNotActivatedProposalCount = approvedNotActivatedProposalCount; }

    public long getRejectedProposalCount() { return rejectedProposalCount; }
    public void setRejectedProposalCount(long rejectedProposalCount) { this.rejectedProposalCount = rejectedProposalCount; }

    public boolean isGovernanceAuditAvailable() { return governanceAuditAvailable; }
    public void setGovernanceAuditAvailable(boolean governanceAuditAvailable) { this.governanceAuditAvailable = governanceAuditAvailable; }

    public boolean isAuditChainIntegrityValid() { return auditChainIntegrityValid; }
    public void setAuditChainIntegrityValid(boolean auditChainIntegrityValid) { this.auditChainIntegrityValid = auditChainIntegrityValid; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
}

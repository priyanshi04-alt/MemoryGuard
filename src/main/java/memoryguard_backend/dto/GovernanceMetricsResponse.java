package memoryguard_backend.dto;

import java.util.Map;

public class GovernanceMetricsResponse {

    private long totalProposals;
    private long pendingProposals;
    private long approvedProposals;
    private long rejectedProposals;
    private long activePolicyVersions;
    private long supersededPolicyVersions;
    private long totalPolicyActivations;
    private long totalPolicyRejections;
    private long totalApprovalActions;
    private long totalGovernanceActions;
    private long unauthorizedGovernanceAttempts;
    private Map<String, Long> proposalCountsByChangeType;
    private Map<String, Long> proposalCountsByState;

    public GovernanceMetricsResponse() {
    }

    public GovernanceMetricsResponse(
            long totalProposals,
            long pendingProposals,
            long approvedProposals,
            long rejectedProposals,
            long activePolicyVersions,
            long supersededPolicyVersions,
            long totalPolicyActivations,
            long totalPolicyRejections,
            long totalApprovalActions,
            long totalGovernanceActions,
            long unauthorizedGovernanceAttempts,
            Map<String, Long> proposalCountsByChangeType,
            Map<String, Long> proposalCountsByState) {
        this.totalProposals = totalProposals;
        this.pendingProposals = pendingProposals;
        this.approvedProposals = approvedProposals;
        this.rejectedProposals = rejectedProposals;
        this.activePolicyVersions = activePolicyVersions;
        this.supersededPolicyVersions = supersededPolicyVersions;
        this.totalPolicyActivations = totalPolicyActivations;
        this.totalPolicyRejections = totalPolicyRejections;
        this.totalApprovalActions = totalApprovalActions;
        this.totalGovernanceActions = totalGovernanceActions;
        this.unauthorizedGovernanceAttempts = unauthorizedGovernanceAttempts;
        this.proposalCountsByChangeType = proposalCountsByChangeType;
        this.proposalCountsByState = proposalCountsByState;
    }

    public long getTotalProposals() { return totalProposals; }
    public void setTotalProposals(long totalProposals) { this.totalProposals = totalProposals; }

    public long getPendingProposals() { return pendingProposals; }
    public void setPendingProposals(long pendingProposals) { this.pendingProposals = pendingProposals; }

    public long getApprovedProposals() { return approvedProposals; }
    public void setApprovedProposals(long approvedProposals) { this.approvedProposals = approvedProposals; }

    public long getRejectedProposals() { return rejectedProposals; }
    public void setRejectedProposals(long rejectedProposals) { this.rejectedProposals = rejectedProposals; }

    public long getActivePolicyVersions() { return activePolicyVersions; }
    public void setActivePolicyVersions(long activePolicyVersions) { this.activePolicyVersions = activePolicyVersions; }

    public long getSupersededPolicyVersions() { return supersededPolicyVersions; }
    public void setSupersededPolicyVersions(long supersededPolicyVersions) { this.supersededPolicyVersions = supersededPolicyVersions; }

    public long getTotalPolicyActivations() { return totalPolicyActivations; }
    public void setTotalPolicyActivations(long totalPolicyActivations) { this.totalPolicyActivations = totalPolicyActivations; }

    public long getTotalPolicyRejections() { return totalPolicyRejections; }
    public void setTotalPolicyRejections(long totalPolicyRejections) { this.totalPolicyRejections = totalPolicyRejections; }

    public long getTotalApprovalActions() { return totalApprovalActions; }
    public void setTotalApprovalActions(long totalApprovalActions) { this.totalApprovalActions = totalApprovalActions; }

    public long getTotalGovernanceActions() { return totalGovernanceActions; }
    public void setTotalGovernanceActions(long totalGovernanceActions) { this.totalGovernanceActions = totalGovernanceActions; }

    public long getUnauthorizedGovernanceAttempts() { return unauthorizedGovernanceAttempts; }
    public void setUnauthorizedGovernanceAttempts(long unauthorizedGovernanceAttempts) { this.unauthorizedGovernanceAttempts = unauthorizedGovernanceAttempts; }

    public Map<String, Long> getProposalCountsByChangeType() { return proposalCountsByChangeType; }
    public void setProposalCountsByChangeType(Map<String, Long> proposalCountsByChangeType) { this.proposalCountsByChangeType = proposalCountsByChangeType; }

    public Map<String, Long> getProposalCountsByState() { return proposalCountsByState; }
    public void setProposalCountsByState(Map<String, Long> proposalCountsByState) { this.proposalCountsByState = proposalCountsByState; }
}

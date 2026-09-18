package memoryguard_backend.dto;

public class OperatorGovernanceActivityResponse {

    private String operatorId;
    private long proposalsCreated;
    private long approvalsPerformed;
    private long rejectionsPerformed;
    private long activationsPerformed;
    private long totalGovernanceActions;

    public OperatorGovernanceActivityResponse() {
    }

    public OperatorGovernanceActivityResponse(
            String operatorId,
            long proposalsCreated,
            long approvalsPerformed,
            long rejectionsPerformed,
            long activationsPerformed,
            long totalGovernanceActions) {
        this.operatorId = operatorId;
        this.proposalsCreated = proposalsCreated;
        this.approvalsPerformed = approvalsPerformed;
        this.rejectionsPerformed = rejectionsPerformed;
        this.activationsPerformed = activationsPerformed;
        this.totalGovernanceActions = totalGovernanceActions;
    }

    public String getOperatorId() { return operatorId; }
    public void setOperatorId(String operatorId) { this.operatorId = operatorId; }

    public long getProposalsCreated() { return proposalsCreated; }
    public void setProposalsCreated(long proposalsCreated) { this.proposalsCreated = proposalsCreated; }

    public long getApprovalsPerformed() { return approvalsPerformed; }
    public void setApprovalsPerformed(long approvalsPerformed) { this.approvalsPerformed = approvalsPerformed; }

    public long getRejectionsPerformed() { return rejectionsPerformed; }
    public void setRejectionsPerformed(long rejectionsPerformed) { this.rejectionsPerformed = rejectionsPerformed; }

    public long getActivationsPerformed() { return activationsPerformed; }
    public void setActivationsPerformed(long activationsPerformed) { this.activationsPerformed = activationsPerformed; }

    public long getTotalGovernanceActions() { return totalGovernanceActions; }
    public void setTotalGovernanceActions(long totalGovernanceActions) { this.totalGovernanceActions = totalGovernanceActions; }
}

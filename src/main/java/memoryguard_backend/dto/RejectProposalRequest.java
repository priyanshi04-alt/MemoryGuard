package memoryguard_backend.dto;

public class RejectProposalRequest {

    private String rejectionReason;

    public RejectProposalRequest() {
    }

    public RejectProposalRequest(String rejectionReason) {
        this.rejectionReason = rejectionReason;
    }

    public String getRejectionReason() {
        return rejectionReason;
    }

    public void setRejectionReason(String rejectionReason) {
        this.rejectionReason = rejectionReason;
    }

    public String reason() {
        return rejectionReason;
    }
}

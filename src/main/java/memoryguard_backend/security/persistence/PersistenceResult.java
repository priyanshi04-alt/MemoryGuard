package memoryguard_backend.security.persistence;

public class PersistenceResult {

    private final String status; // PERMITTED, QUARANTINED, DENIED
    private final Long memoryId;
    private final Long quarantineId;
    private final Long deniedRecordId;
    private final String policyRule;
    private final String explanation;

    public PersistenceResult(
            String status,
            Long memoryId,
            Long quarantineId,
            Long deniedRecordId,
            String policyRule,
            String explanation) {

        this.status = status != null ? status : "QUARANTINED";
        this.memoryId = memoryId;
        this.quarantineId = quarantineId;
        this.deniedRecordId = deniedRecordId;
        this.policyRule = policyRule != null ? policyRule : "UNKNOWN_POLICY";
        this.explanation = explanation != null ? explanation : "";
    }

    public String getStatus() {
        return status;
    }

    public Long getMemoryId() {
        return memoryId;
    }

    public Long getQuarantineId() {
        return quarantineId;
    }

    public Long getDeniedRecordId() {
        return deniedRecordId;
    }

    public String getPolicyRule() {
        return policyRule;
    }

    public String getExplanation() {
        return explanation;
    }

    public boolean isPermitted() {
        return "PERMITTED".equalsIgnoreCase(status);
    }

    public boolean isQuarantined() {
        return "QUARANTINED".equalsIgnoreCase(status);
    }

    public boolean isDenied() {
        return "DENIED".equalsIgnoreCase(status);
    }
}

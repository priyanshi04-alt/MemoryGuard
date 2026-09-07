package memoryguard_backend;

public class AdversarialSample {

    private String id;
    private String memoryText;
    private String provenance;
    private String category;
    private String expectedClass; // MALICIOUS, BENIGN, AMBIGUOUS
    private String expectedDecision; // ALLOW, REVIEW, BLOCK
    private String explanation;
    private String pairId;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getMemoryText() {
        return memoryText;
    }

    public void setMemoryText(String memoryText) {
        this.memoryText = memoryText;
    }

    public String getProvenance() {
        return provenance;
    }

    public void setProvenance(String provenance) {
        this.provenance = provenance;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getExpectedClass() {
        return expectedClass;
    }

    public void setExpectedClass(String expectedClass) {
        this.expectedClass = expectedClass;
    }

    public String getExpectedDecision() {
        return expectedDecision;
    }

    public void setExpectedDecision(String expectedDecision) {
        this.expectedDecision = expectedDecision;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public String getPairId() {
        return pairId;
    }

    public void setPairId(String pairId) {
        this.pairId = pairId;
    }
}

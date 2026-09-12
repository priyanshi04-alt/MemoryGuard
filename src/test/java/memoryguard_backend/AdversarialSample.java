package memoryguard_backend;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AdversarialSample {

    private String id;
    private String attackId;
    private String memoryText;
    private String memoryContent;
    private String provenance;
    private String category;
    private String attackCategory;
    private String expectedClass; // MALICIOUS, BENIGN, AMBIGUOUS
    private String expectedDecision; // ALLOW, REVIEW, BLOCK
    private String explanation;
    private String expectedSecurityReason;
    private String pairId;

    public String getId() {
        return attackId != null ? attackId : id;
    }

    public void setId(String id) {
        this.id = id;
        if (this.attackId == null) this.attackId = id;
    }

    public String getAttackId() {
        return attackId != null ? attackId : id;
    }

    public void setAttackId(String attackId) {
        this.attackId = attackId;
        if (this.id == null) this.id = attackId;
    }

    public String getMemoryText() {
        return memoryContent != null ? memoryContent : memoryText;
    }

    public void setMemoryText(String memoryText) {
        this.memoryText = memoryText;
        if (this.memoryContent == null) this.memoryContent = memoryText;
    }

    public String getMemoryContent() {
        return memoryContent != null ? memoryContent : memoryText;
    }

    public void setMemoryContent(String memoryContent) {
        this.memoryContent = memoryContent;
        if (this.memoryText == null) this.memoryText = memoryContent;
    }

    public String getProvenance() {
        return provenance;
    }

    public void setProvenance(String provenance) {
        this.provenance = provenance;
    }

    public String getCategory() {
        return attackCategory != null ? attackCategory : category;
    }

    public void setCategory(String category) {
        this.category = category;
        if (this.attackCategory == null) this.attackCategory = category;
    }

    public String getAttackCategory() {
        return attackCategory != null ? attackCategory : category;
    }

    public void setAttackCategory(String attackCategory) {
        this.attackCategory = attackCategory;
        if (this.category == null) this.category = attackCategory;
    }

    public String getExpectedClass() {
        if (expectedClass != null) return expectedClass;
        if ("BENIGN".equalsIgnoreCase(getCategory()) || "ALLOW".equalsIgnoreCase(expectedDecision)) return "BENIGN";
        if ("AMBIGUOUS_CASE".equalsIgnoreCase(getCategory())) return "AMBIGUOUS";
        return "MALICIOUS";
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
        return expectedSecurityReason != null ? expectedSecurityReason : explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
        if (this.expectedSecurityReason == null) this.expectedSecurityReason = explanation;
    }

    public String getExpectedSecurityReason() {
        return expectedSecurityReason != null ? expectedSecurityReason : explanation;
    }

    public void setExpectedSecurityReason(String expectedSecurityReason) {
        this.expectedSecurityReason = expectedSecurityReason;
        if (this.explanation == null) this.explanation = expectedSecurityReason;
    }

    public String getPairId() {
        return pairId;
    }

    public void setPairId(String pairId) {
        this.pairId = pairId;
    }
}

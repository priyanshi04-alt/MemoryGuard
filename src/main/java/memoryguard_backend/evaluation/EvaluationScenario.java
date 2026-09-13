package memoryguard_backend.evaluation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class EvaluationScenario {

    private String id;
    private String attackId;
    private String caseId;
    private String memoryContent;
    private String provenance; // USER_INPUT, SYSTEM, AGENT_SCRATCHPAD, RETRIEVED, EXTERNAL_TOOL, UNTRUSTED
    private String context;
    private String expectedCategory; // e.g. NORMAL, PROMPT_INJECTION, INSTRUCTION_HIJACKING, SENSITIVE_INFORMATION, etc.
    private String attackCategory;
    private String expectedDecision; // ALLOW, REVIEW, BLOCK
    private String expectedRiskLevel; // LOW, MEDIUM, HIGH, CRITICAL
    private Integer expectedRiskMin;
    private Integer expectedRiskMax;
    private String attackType;
    private String explanation;
    private String expectedSecurityReason;
    private String pairId;
    private boolean isAdversarial;

    public EvaluationScenario() {}

    public EvaluationScenario(String id, String memoryContent, String provenance, String context,
                              String expectedCategory, String expectedDecision, Integer expectedRiskMin,
                              Integer expectedRiskMax, String attackType, String explanation,
                              String pairId, boolean isAdversarial) {
        this.id = id;
        this.attackId = id;
        this.caseId = id;
        this.memoryContent = memoryContent;
        this.provenance = provenance;
        this.context = context;
        this.expectedCategory = expectedCategory;
        this.attackCategory = expectedCategory;
        this.expectedDecision = expectedDecision;
        this.expectedRiskMin = expectedRiskMin;
        this.expectedRiskMax = expectedRiskMax;
        this.attackType = attackType;
        this.explanation = explanation;
        this.expectedSecurityReason = explanation;
        this.pairId = pairId;
        this.isAdversarial = isAdversarial;
    }

    public String getId() {
        if (caseId != null) return caseId;
        if (attackId != null) return attackId;
        return id;
    }

    public void setId(String id) {
        this.id = id;
        if (this.attackId == null) this.attackId = id;
        if (this.caseId == null) this.caseId = id;
    }

    public String getCaseId() {
        return getId();
    }

    public void setCaseId(String caseId) {
        this.caseId = caseId;
        if (this.id == null) this.id = caseId;
        if (this.attackId == null) this.attackId = caseId;
    }

    public String getAttackId() {
        return getId();
    }

    public void setAttackId(String attackId) {
        this.attackId = attackId;
        if (this.id == null) this.id = attackId;
        if (this.caseId == null) this.caseId = attackId;
    }

    public String getMemoryContent() {
        return memoryContent;
    }

    public void setMemoryContent(String memoryContent) {
        this.memoryContent = memoryContent;
    }

    public String getProvenance() {
        return provenance;
    }

    public void setProvenance(String provenance) {
        this.provenance = provenance;
    }

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }

    public String getExpectedCategory() {
        return attackCategory != null ? attackCategory : expectedCategory;
    }

    public void setExpectedCategory(String expectedCategory) {
        this.expectedCategory = expectedCategory;
        if (this.attackCategory == null) this.attackCategory = expectedCategory;
    }

    public String getAttackCategory() {
        return attackCategory != null ? attackCategory : expectedCategory;
    }

    public void setAttackCategory(String attackCategory) {
        this.attackCategory = attackCategory;
        if (this.expectedCategory == null) this.expectedCategory = attackCategory;
    }

    public String getExpectedDecision() {
        return expectedDecision;
    }

    public void setExpectedDecision(String expectedDecision) {
        this.expectedDecision = expectedDecision;
    }

    public String getExpectedRiskLevel() {
        return expectedRiskLevel;
    }

    public void setExpectedRiskLevel(String expectedRiskLevel) {
        this.expectedRiskLevel = expectedRiskLevel;
    }

    public Integer getExpectedRiskMin() {
        return expectedRiskMin;
    }

    public void setExpectedRiskMin(Integer expectedRiskMin) {
        this.expectedRiskMin = expectedRiskMin;
    }

    public Integer getExpectedRiskMax() {
        return expectedRiskMax;
    }

    public void setExpectedRiskMax(Integer expectedRiskMax) {
        this.expectedRiskMax = expectedRiskMax;
    }

    public String getAttackType() {
        return attackType;
    }

    public void setAttackType(String attackType) {
        this.attackType = attackType;
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

    public boolean isAdversarial() {
        return isAdversarial;
    }

    public void setAdversarial(boolean adversarial) {
        isAdversarial = adversarial;
    }
}

package memoryguard_backend.evaluation;

import java.util.List;

public class EvaluationResult {

    private String scenarioId;
    private String attackId;
    private String category;
    private String attackCategory;
    private String provenance;
    private String attackType;
    private String memoryContent;
    private String expectedDecision; // ALLOW, REVIEW, BLOCK
    private String expectedRiskLevel; // LOW, MEDIUM, HIGH, CRITICAL
    private String expectedSecurityReason;
    private String actualDecision;   // ALLOW, REVIEW, BLOCK
    private String actualStatus;     // SAFE, QUARANTINED, DENIED
    private String actualFinalState; // PERMITTED, QUARANTINED, DENIED
    private int riskScore;
    private String riskLevel;
    private List<String> ruleFindings;
    private List<String> semanticSignals;
    private List<String> riskFactors;
    private List<String> contributingFactors;
    private List<String> analyzerContributions;
    private boolean ruleDetected;
    private boolean semanticDetected;
    private String detectionAttribution; // RULE_ONLY, SEMANTIC_ONLY, BOTH, NEITHER
    private String decisionReason;
    private String policyReason;
    private String explanation;
    private double latencyMs;
    private boolean passed;
    private boolean isFalsePositive;
    private boolean isFalseNegative;
    private boolean isAmbiguous;
    private String failureDetails;

    public EvaluationResult() {}

    public String getScenarioId() {
        return attackId != null ? attackId : scenarioId;
    }

    public void setScenarioId(String scenarioId) {
        this.scenarioId = scenarioId;
        if (this.attackId == null) this.attackId = scenarioId;
    }

    public String getAttackId() {
        return attackId != null ? attackId : scenarioId;
    }

    public void setAttackId(String attackId) {
        this.attackId = attackId;
        if (this.scenarioId == null) this.scenarioId = attackId;
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

    public String getProvenance() {
        return provenance;
    }

    public void setProvenance(String provenance) {
        this.provenance = provenance;
    }

    public String getAttackType() {
        return attackType;
    }

    public void setAttackType(String attackType) {
        this.attackType = attackType;
    }

    public String getMemoryContent() {
        return memoryContent;
    }

    public void setMemoryContent(String memoryContent) {
        this.memoryContent = memoryContent;
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

    public String getExpectedSecurityReason() {
        return expectedSecurityReason;
    }

    public void setExpectedSecurityReason(String expectedSecurityReason) {
        this.expectedSecurityReason = expectedSecurityReason;
    }

    public String getActualDecision() {
        return actualDecision;
    }

    public void setActualDecision(String actualDecision) {
        this.actualDecision = actualDecision;
    }

    public String getActualStatus() {
        return actualStatus;
    }

    public void setActualStatus(String actualStatus) {
        this.actualStatus = actualStatus;
        if (this.actualFinalState == null) {
            this.actualFinalState = "SAFE".equals(actualStatus) ? "PERMITTED" : ("DENIED".equals(actualStatus) || "BLOCKED".equals(actualStatus) ? "DENIED" : "QUARANTINED");
        }
    }

    public String getActualFinalState() {
        return actualFinalState != null ? actualFinalState : ("SAFE".equals(actualStatus) ? "PERMITTED" : ("DENIED".equals(actualStatus) || "BLOCKED".equals(actualStatus) ? "DENIED" : "QUARANTINED"));
    }

    public void setActualFinalState(String actualFinalState) {
        this.actualFinalState = actualFinalState;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public List<String> getRuleFindings() {
        return ruleFindings;
    }

    public void setRuleFindings(List<String> ruleFindings) {
        this.ruleFindings = ruleFindings;
    }

    public List<String> getSemanticSignals() {
        return semanticSignals;
    }

    public void setSemanticSignals(List<String> semanticSignals) {
        this.semanticSignals = semanticSignals;
    }

    public List<String> getRiskFactors() {
        return riskFactors != null ? riskFactors : contributingFactors;
    }

    public void setRiskFactors(List<String> riskFactors) {
        this.riskFactors = riskFactors;
        if (this.contributingFactors == null) this.contributingFactors = riskFactors;
    }

    public List<String> getContributingFactors() {
        return contributingFactors != null ? contributingFactors : riskFactors;
    }

    public void setContributingFactors(List<String> contributingFactors) {
        this.contributingFactors = contributingFactors;
        if (this.riskFactors == null) this.riskFactors = contributingFactors;
    }

    public List<String> getAnalyzerContributions() {
        return analyzerContributions;
    }

    public void setAnalyzerContributions(List<String> analyzerContributions) {
        this.analyzerContributions = analyzerContributions;
    }

    public boolean isRuleDetected() {
        return ruleDetected;
    }

    public void setRuleDetected(boolean ruleDetected) {
        this.ruleDetected = ruleDetected;
    }

    public boolean isSemanticDetected() {
        return semanticDetected;
    }

    public void setSemanticDetected(boolean semanticDetected) {
        this.semanticDetected = semanticDetected;
    }

    public String getDetectionAttribution() {
        return detectionAttribution;
    }

    public void setDetectionAttribution(String detectionAttribution) {
        this.detectionAttribution = detectionAttribution;
    }

    public String getDecisionReason() {
        return policyReason != null ? policyReason : decisionReason;
    }

    public void setDecisionReason(String decisionReason) {
        this.decisionReason = decisionReason;
        if (this.policyReason == null) this.policyReason = decisionReason;
    }

    public String getPolicyReason() {
        return policyReason != null ? policyReason : decisionReason;
    }

    public void setPolicyReason(String policyReason) {
        this.policyReason = policyReason;
        if (this.decisionReason == null) this.decisionReason = policyReason;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public double getLatencyMs() {
        return latencyMs;
    }

    public void setLatencyMs(double latencyMs) {
        this.latencyMs = latencyMs;
    }

    public boolean isPassed() {
        return passed;
    }

    public void setPassed(boolean passed) {
        this.passed = passed;
    }

    public boolean isFalsePositive() {
        return isFalsePositive;
    }

    public void setFalsePositive(boolean falsePositive) {
        isFalsePositive = falsePositive;
    }

    public boolean isFalseNegative() {
        return isFalseNegative;
    }

    public void setFalseNegative(boolean falseNegative) {
        isFalseNegative = falseNegative;
    }

    public boolean isAmbiguous() {
        return isAmbiguous;
    }

    public void setAmbiguous(boolean ambiguous) {
        isAmbiguous = ambiguous;
    }

    public String getFailureDetails() {
        return failureDetails;
    }

    public void setFailureDetails(String failureDetails) {
        this.failureDetails = failureDetails;
    }
}

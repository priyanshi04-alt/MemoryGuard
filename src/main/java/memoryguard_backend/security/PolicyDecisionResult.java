package memoryguard_backend.security;

import java.util.List;

public class PolicyDecisionResult {

    private final PolicyDecision decision;
    private final int riskScore;
    private final String riskLevel;
    private final double confidence;
    private final String policyRule;
    private final String explanation;
    private final List<String> contributingFactors;
    private final String persistenceStatus;

    public PolicyDecisionResult(
            PolicyDecision decision,
            int riskScore,
            String riskLevel,
            double confidence,
            String policyRule,
            String explanation,
            List<String> contributingFactors,
            String persistenceStatus) {

        this.decision = decision;
        this.riskScore = Math.min(100, Math.max(0, riskScore));
        this.riskLevel = riskLevel != null ? riskLevel : deriveRiskLevel(this.riskScore);
        this.confidence = Math.min(1.0, Math.max(0.0, confidence));
        this.policyRule = policyRule != null ? policyRule : "DEFAULT_POLICY";
        this.explanation = explanation != null ? explanation : "";
        this.contributingFactors = contributingFactors != null ? List.copyOf(contributingFactors) : List.of();
        this.persistenceStatus = persistenceStatus != null ? persistenceStatus : derivePersistenceStatus(decision);
    }

    public PolicyDecisionResult(PolicyDecision decision, int riskScore, String explanation, List<String> contributingFactors) {
        this(
                decision,
                riskScore,
                deriveRiskLevel(riskScore),
                1.0,
                "THRESHOLD_POLICY",
                explanation,
                contributingFactors,
                derivePersistenceStatus(decision)
        );
    }

    public PolicyDecision getDecision() {
        return decision;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getPolicyRule() {
        return policyRule;
    }

    public String getExplanation() {
        return explanation;
    }

    public List<String> getContributingFactors() {
        return contributingFactors;
    }

    public String getPersistenceStatus() {
        return persistenceStatus;
    }

    public boolean isPersistencePermitted() {
        return "PERMITTED".equalsIgnoreCase(persistenceStatus);
    }

    private static String deriveRiskLevel(int score) {
        if (score >= 80) return "HIGH";
        if (score >= 50) return "MEDIUM";
        return "LOW";
    }

    private static String derivePersistenceStatus(PolicyDecision decision) {
        if (decision == null) return "QUARANTINED";
        switch (decision) {
            case ALLOW: return "PERMITTED";
            case REVIEW: return "QUARANTINED";
            case BLOCK: return "DENIED";
            default: return "QUARANTINED";
        }
    }
}

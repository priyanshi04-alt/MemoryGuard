package memoryguard_backend.security.explainability;

import memoryguard_backend.security.PolicyDecision;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;

/**
 * Domain model capturing complete security decision explainability and threat intelligence metadata.
 * Does NOT store or return sensitive memory plaintext.
 */
public class SecurityDecisionExplanation {

    private final Long memoryId;
    private final String correlationId;
    private final PolicyDecision finalDecision;
    private final int riskScore;
    private final String riskLevel;
    private final double confidence;
    private final String policyRule;
    private final List<ThreatCategory> threatCategories;
    private final List<ContributingFactor> contributingFactors;
    private final List<String> analyzerFindings;
    private final EvidenceChain evidenceChain;
    private final String explanationSummary;
    private final LocalDateTime timestamp;

    public SecurityDecisionExplanation(
            Long memoryId,
            String correlationId,
            PolicyDecision finalDecision,
            int riskScore,
            String riskLevel,
            double confidence,
            String policyRule,
            List<ThreatCategory> threatCategories,
            List<ContributingFactor> contributingFactors,
            List<String> analyzerFindings,
            EvidenceChain evidenceChain,
            String explanationSummary,
            LocalDateTime timestamp) {

        this.memoryId = memoryId;
        this.correlationId = correlationId != null ? correlationId : "";
        this.finalDecision = finalDecision != null ? finalDecision : PolicyDecision.REVIEW;
        this.riskScore = Math.min(100, Math.max(0, riskScore));
        this.riskLevel = riskLevel != null ? riskLevel : "MEDIUM";
        this.confidence = Math.min(1.0, Math.max(0.0, confidence));
        this.policyRule = policyRule != null ? policyRule : "DEFAULT_POLICY";
        this.threatCategories = threatCategories != null ? List.copyOf(threatCategories) : List.of(ThreatCategory.UNKNOWN);
        this.contributingFactors = contributingFactors != null ? List.copyOf(contributingFactors) : List.of();
        this.analyzerFindings = analyzerFindings != null ? List.copyOf(analyzerFindings) : List.of();
        this.evidenceChain = evidenceChain;
        this.explanationSummary = explanationSummary != null ? explanationSummary : "";
        this.timestamp = timestamp != null ? timestamp : LocalDateTime.now();
    }

    public Long getMemoryId() {
        return memoryId;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public PolicyDecision getFinalDecision() {
        return finalDecision;
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

    public List<ThreatCategory> getThreatCategories() {
        return threatCategories;
    }

    public List<ContributingFactor> getContributingFactors() {
        return contributingFactors;
    }

    public List<String> getAnalyzerFindings() {
        return analyzerFindings;
    }

    public EvidenceChain getEvidenceChain() {
        return evidenceChain;
    }

    public String getExplanationSummary() {
        return explanationSummary;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityDecisionExplanation that = (SecurityDecisionExplanation) o;
        return riskScore == that.riskScore &&
                Double.compare(that.confidence, confidence) == 0 &&
                Objects.equals(memoryId, that.memoryId) &&
                Objects.equals(correlationId, that.correlationId) &&
                finalDecision == that.finalDecision &&
                Objects.equals(riskLevel, that.riskLevel) &&
                Objects.equals(policyRule, that.policyRule) &&
                Objects.equals(threatCategories, that.threatCategories) &&
                Objects.equals(contributingFactors, that.contributingFactors) &&
                Objects.equals(analyzerFindings, that.analyzerFindings) &&
                Objects.equals(evidenceChain, that.evidenceChain) &&
                Objects.equals(explanationSummary, that.explanationSummary);
    }

    @Override
    public int hashCode() {
        return Objects.hash(memoryId, correlationId, finalDecision, riskScore, riskLevel, confidence, policyRule, threatCategories, contributingFactors, analyzerFindings, evidenceChain, explanationSummary);
    }

    @Override
    public String toString() {
        return "SecurityDecisionExplanation{" +
                "memoryId=" + memoryId +
                ", correlationId='" + correlationId + '\'' +
                ", finalDecision=" + finalDecision +
                ", riskScore=" + riskScore +
                ", riskLevel='" + riskLevel + '\'' +
                ", confidence=" + confidence +
                ", policyRule='" + policyRule + '\'' +
                ", threatCategories=" + threatCategories +
                ", contributingFactors=" + contributingFactors +
                ", analyzerFindings=" + analyzerFindings +
                ", evidenceChain=" + evidenceChain +
                ", explanationSummary='" + explanationSummary + '\'' +
                ", timestamp=" + timestamp +
                '}';
    }
}

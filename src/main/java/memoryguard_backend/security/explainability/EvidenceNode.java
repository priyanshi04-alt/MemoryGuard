package memoryguard_backend.security.explainability;

import memoryguard_backend.security.PolicyDecision;
import java.util.Objects;

/**
 * Represents a single node in the explicit security evidence chain:
 * Analyzer Finding -> Risk Contribution -> Cumulative Risk Score -> Policy Rule -> Decision.
 */
public class EvidenceNode {

    private final String analyzerType;
    private final String finding;
    private final int riskContribution;
    private final int cumulativeScore;
    private final String policyRule;
    private final PolicyDecision decision;

    public EvidenceNode(
            String analyzerType,
            String finding,
            int riskContribution,
            int cumulativeScore,
            String policyRule,
            PolicyDecision decision) {

        this.analyzerType = analyzerType != null ? analyzerType : "UNKNOWN";
        this.finding = finding != null ? finding : "";
        this.riskContribution = Math.min(100, Math.max(0, riskContribution));
        this.cumulativeScore = Math.min(100, Math.max(0, cumulativeScore));
        this.policyRule = policyRule != null ? policyRule : "DEFAULT";
        this.decision = decision != null ? decision : PolicyDecision.REVIEW;
    }

    public String getAnalyzerType() {
        return analyzerType;
    }

    public String getFinding() {
        return finding;
    }

    public int getRiskContribution() {
        return riskContribution;
    }

    public int getCumulativeScore() {
        return cumulativeScore;
    }

    public String getPolicyRule() {
        return policyRule;
    }

    public PolicyDecision getDecision() {
        return decision;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EvidenceNode node = (EvidenceNode) o;
        return riskContribution == node.riskContribution &&
                cumulativeScore == node.cumulativeScore &&
                Objects.equals(analyzerType, node.analyzerType) &&
                Objects.equals(finding, node.finding) &&
                Objects.equals(policyRule, node.policyRule) &&
                decision == node.decision;
    }

    @Override
    public int hashCode() {
        return Objects.hash(analyzerType, finding, riskContribution, cumulativeScore, policyRule, decision);
    }

    @Override
    public String toString() {
        return "EvidenceNode{" +
                "analyzerType='" + analyzerType + '\'' +
                ", finding='" + finding + '\'' +
                ", riskContribution=" + riskContribution +
                ", cumulativeScore=" + cumulativeScore +
                ", policyRule='" + policyRule + '\'' +
                ", decision=" + decision +
                '}';
    }
}

package memoryguard_backend.security.explainability;

import memoryguard_backend.security.PolicyDecision;
import java.util.List;
import java.util.Objects;

/**
 * Traces a security decision back to its raw security evidence through an explicit chain:
 * Analyzer Finding -> Risk Contribution -> Risk Score -> Policy Rule -> Final Decision.
 */
public class EvidenceChain {

    private final List<EvidenceNode> nodes;
    private final int overallRiskScore;
    private final String policyRule;
    private final PolicyDecision finalDecision;

    public EvidenceChain(List<EvidenceNode> nodes, int overallRiskScore, String policyRule, PolicyDecision finalDecision) {
        this.nodes = nodes != null ? List.copyOf(nodes) : List.of();
        this.overallRiskScore = Math.min(100, Math.max(0, overallRiskScore));
        this.policyRule = policyRule != null ? policyRule : "DEFAULT";
        this.finalDecision = finalDecision != null ? finalDecision : PolicyDecision.REVIEW;
    }

    public List<EvidenceNode> getNodes() {
        return nodes;
    }

    public int getOverallRiskScore() {
        return overallRiskScore;
    }

    public String getPolicyRule() {
        return policyRule;
    }

    public PolicyDecision getFinalDecision() {
        return finalDecision;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EvidenceChain chain = (EvidenceChain) o;
        return overallRiskScore == chain.overallRiskScore &&
                Objects.equals(nodes, chain.nodes) &&
                Objects.equals(policyRule, chain.policyRule) &&
                finalDecision == chain.finalDecision;
    }

    @Override
    public int hashCode() {
        return Objects.hash(nodes, overallRiskScore, policyRule, finalDecision);
    }

    @Override
    public String toString() {
        return "EvidenceChain{" +
                "nodes=" + nodes +
                ", overallRiskScore=" + overallRiskScore +
                ", policyRule='" + policyRule + '\'' +
                ", finalDecision=" + finalDecision +
                '}';
    }
}

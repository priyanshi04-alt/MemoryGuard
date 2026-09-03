package memoryguard_backend.security;

import java.util.Objects;

/**
 * Domain model representing an individual semantic security signal detected during memory evaluation.
 * Each signal provides granular evidence, risk contribution, confidence, and context snippet.
 */
public class SemanticSecuritySignal {

    private final SemanticSignalType signalType;
    private final int riskContribution;
    private final double confidence;
    private final String evidence;
    private final String snippet;
    private final String source;

    public SemanticSecuritySignal(
            SemanticSignalType signalType,
            int riskContribution,
            double confidence,
            String evidence,
            String snippet,
            String source) {

        this.signalType = Objects.requireNonNull(signalType, "Signal type cannot be null");
        this.riskContribution = Math.max(0, Math.min(100, riskContribution));
        this.confidence = Math.max(0.0, Math.min(1.0, confidence));
        this.evidence = evidence != null ? evidence : "";
        this.snippet = snippet;
        this.source = source != null ? source : "semantic-analyzer";
    }

    public SemanticSecuritySignal(
            SemanticSignalType signalType,
            int riskContribution,
            double confidence,
            String evidence) {

        this(signalType, riskContribution, confidence, evidence, null, "semantic-analyzer");
    }

    public SemanticSignalType getSignalType() {
        return signalType;
    }

    public int getRiskContribution() {
        return riskContribution;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getEvidence() {
        return evidence;
    }

    public String getSnippet() {
        return snippet;
    }

    public String getSource() {
        return source;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SemanticSecuritySignal that = (SemanticSecuritySignal) o;
        return riskContribution == that.riskContribution &&
                Double.compare(that.confidence, confidence) == 0 &&
                signalType == that.signalType &&
                Objects.equals(evidence, that.evidence) &&
                Objects.equals(snippet, that.snippet) &&
                Objects.equals(source, that.source);
    }

    @Override
    public int hashCode() {
        return Objects.hash(signalType, riskContribution, confidence, evidence, snippet, source);
    }

    @Override
    public String toString() {
        return "SemanticSecuritySignal{" +
                "signalType=" + signalType +
                ", riskContribution=" + riskContribution +
                ", confidence=" + confidence +
                ", evidence='" + evidence + '\'' +
                ", snippet='" + snippet + '\'' +
                ", source='" + source + '\'' +
                '}';
    }
}

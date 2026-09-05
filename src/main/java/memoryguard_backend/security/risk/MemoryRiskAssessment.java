package memoryguard_backend.security.risk;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Structured risk assessment output produced by the Memory Security Risk Aggregator.
 * <p>
 * This model contains aggregated security risk scores, risk levels, and contributing signals.
 * It strictly represents Risk Assessment and does NOT contain Policy Decisions (ALLOW / REVIEW / BLOCK).
 */
public class MemoryRiskAssessment {

    private int riskScore;
    private String riskLevel;
    private int signalCount;
    private List<AggregatedSignalContribution> signals = new ArrayList<>();

    public MemoryRiskAssessment() {
    }

    public MemoryRiskAssessment(int riskScore, String riskLevel, List<AggregatedSignalContribution> signals) {
        this.riskScore = Math.min(100, Math.max(0, riskScore));
        this.riskLevel = riskLevel != null ? riskLevel : "LOW";
        this.signals = signals != null ? signals : new ArrayList<>();
        this.signalCount = this.signals.size();
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = Math.min(100, Math.max(0, riskScore));
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public int getSignalCount() {
        return signalCount;
    }

    public void setSignalCount(int signalCount) {
        this.signalCount = signalCount;
    }

    public List<AggregatedSignalContribution> getSignals() {
        return signals;
    }

    public void setSignals(List<AggregatedSignalContribution> signals) {
        this.signals = signals != null ? signals : new ArrayList<>();
        this.signalCount = this.signals.size();
    }

    public void addSignal(AggregatedSignalContribution signal) {
        if (signal != null) {
            this.signals.add(signal);
            this.signalCount = this.signals.size();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MemoryRiskAssessment assessment = (MemoryRiskAssessment) o;
        return riskScore == assessment.riskScore &&
                signalCount == assessment.signalCount &&
                Objects.equals(riskLevel, assessment.riskLevel) &&
                Objects.equals(signals, assessment.signals);
    }

    @Override
    public int hashCode() {
        return Objects.hash(riskScore, riskLevel, signalCount, signals);
    }

    @Override
    public String toString() {
        return "MemoryRiskAssessment{" +
                "riskScore=" + riskScore +
                ", riskLevel='" + riskLevel + '\'' +
                ", signalCount=" + signalCount +
                '}';
    }
}

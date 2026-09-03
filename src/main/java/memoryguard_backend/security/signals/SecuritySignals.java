package memoryguard_backend.security.signals;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * SecuritySignals model representing extracted security-relevant features from a memory item.
 * <p>
 * SCORE SEMANTICS:
 * All scores are normalized floating-point numbers between 0.0 and 1.0.
 * <ul>
 *   <li><b>provenanceTrustScore</b>: 0.0 (completely untrusted/unknown origin) -> 1.0 (fully trusted system origin)</li>
 *   <li><b>sourceReliabilityScore</b>: 0.0 (unreliable source metadata) -> 1.0 (highly reliable source origin)</li>
 *   <li><b>contextConsistencyScore</b>: 0.0 (severe internal inconsistency/mismatch) -> 1.0 (fully consistent context)</li>
 *   <li><b>provenanceCompletenessScore</b>: 0.0 (missing/incomplete provenance data) -> 1.0 (complete provenance data)</li>
 *   <li><b>sensitivityScore</b>: 0.0 (no sensitivity signal) -> 1.0 (high credential/PII/secret exposure signal)</li>
 *   <li><b>anomalyScore</b>: 0.0 (no metadata anomalies) -> 1.0 (high metadata/structural anomaly signal)</li>
 *   <li><b>instructionLikeScore</b>: 0.0 (harmless text) -> 1.0 (strong system instruction override or prompt injection attempt)</li>
 *   <li><b>privilegeRiskScore</b>: 0.0 (no privilege relevance) -> 1.0 (high administrative/auth/root relevance)</li>
 *   <li><b>temporalAnomalyScore</b>: 0.0 (valid temporal sequence) -> 1.0 (future timestamp or impossible ordering)</li>
 * </ul>
 * <p>
 * IMPORTANT: These are raw security SIGNALS/FEATURES, NOT the final ALLOW/BLOCK policy decision.
 */
public class SecuritySignals {

    private Long memoryId;
    private String correlationId;

    // Trust & Context Quality Scores [0.0 - 1.0]
    private double provenanceTrustScore;
    private double sourceReliabilityScore;
    private double contextConsistencyScore;
    private double provenanceCompletenessScore;

    // Security Risk & Threat Feature Scores [0.0 - 1.0]
    private double sensitivityScore;
    private double anomalyScore;
    private double instructionLikeScore;
    private double privilegeRiskScore;
    private double temporalAnomalyScore;

    // Explainable indicators
    private List<SecurityIndicator> indicators = new ArrayList<>();

    // Diagnostic / Execution Metadata
    private Map<String, Object> analysisMetadata = new HashMap<>();

    public SecuritySignals() {
    }

    public SecuritySignals(
            Long memoryId,
            String correlationId,
            double provenanceTrustScore,
            double sourceReliabilityScore,
            double contextConsistencyScore,
            double provenanceCompletenessScore,
            double sensitivityScore,
            double anomalyScore,
            double instructionLikeScore,
            double privilegeRiskScore,
            double temporalAnomalyScore,
            List<SecurityIndicator> indicators,
            Map<String, Object> analysisMetadata) {

        this.memoryId = memoryId;
        this.correlationId = correlationId;
        this.provenanceTrustScore = provenanceTrustScore;
        this.sourceReliabilityScore = sourceReliabilityScore;
        this.contextConsistencyScore = contextConsistencyScore;
        this.provenanceCompletenessScore = provenanceCompletenessScore;
        this.sensitivityScore = sensitivityScore;
        this.anomalyScore = anomalyScore;
        this.instructionLikeScore = instructionLikeScore;
        this.privilegeRiskScore = privilegeRiskScore;
        this.temporalAnomalyScore = temporalAnomalyScore;
        this.indicators = indicators != null ? indicators : new ArrayList<>();
        this.analysisMetadata = analysisMetadata != null ? analysisMetadata : new HashMap<>();
    }

    public Long getMemoryId() {
        return memoryId;
    }

    public void setMemoryId(Long memoryId) {
        this.memoryId = memoryId;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
    }

    public double getProvenanceTrustScore() {
        return provenanceTrustScore;
    }

    public void setProvenanceTrustScore(double provenanceTrustScore) {
        this.provenanceTrustScore = provenanceTrustScore;
    }

    public double getSourceReliabilityScore() {
        return sourceReliabilityScore;
    }

    public void setSourceReliabilityScore(double sourceReliabilityScore) {
        this.sourceReliabilityScore = sourceReliabilityScore;
    }

    public double getContextConsistencyScore() {
        return contextConsistencyScore;
    }

    public void setContextConsistencyScore(double contextConsistencyScore) {
        this.contextConsistencyScore = contextConsistencyScore;
    }

    public double getProvenanceCompletenessScore() {
        return provenanceCompletenessScore;
    }

    public void setProvenanceCompletenessScore(double provenanceCompletenessScore) {
        this.provenanceCompletenessScore = provenanceCompletenessScore;
    }

    public double getSensitivityScore() {
        return sensitivityScore;
    }

    public void setSensitivityScore(double sensitivityScore) {
        this.sensitivityScore = sensitivityScore;
    }

    public double getAnomalyScore() {
        return anomalyScore;
    }

    public void setAnomalyScore(double anomalyScore) {
        this.anomalyScore = anomalyScore;
    }

    public double getInstructionLikeScore() {
        return instructionLikeScore;
    }

    public void setInstructionLikeScore(double instructionLikeScore) {
        this.instructionLikeScore = instructionLikeScore;
    }

    public double getPrivilegeRiskScore() {
        return privilegeRiskScore;
    }

    public void setPrivilegeRiskScore(double privilegeRiskScore) {
        this.privilegeRiskScore = privilegeRiskScore;
    }

    public double getTemporalAnomalyScore() {
        return temporalAnomalyScore;
    }

    public void setTemporalAnomalyScore(double temporalAnomalyScore) {
        this.temporalAnomalyScore = temporalAnomalyScore;
    }

    public List<SecurityIndicator> getIndicators() {
        return indicators;
    }

    public void setIndicators(List<SecurityIndicator> indicators) {
        this.indicators = indicators != null ? indicators : new ArrayList<>();
    }

    public void addIndicator(SecurityIndicator indicator) {
        if (indicator != null) {
            this.indicators.add(indicator);
        }
    }

    public Map<String, Object> getAnalysisMetadata() {
        return analysisMetadata;
    }

    public void setAnalysisMetadata(Map<String, Object> analysisMetadata) {
        this.analysisMetadata = analysisMetadata != null ? analysisMetadata : new HashMap<>();
    }

    public void addMetadata(String key, Object value) {
        this.analysisMetadata.put(key, value);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecuritySignals that = (SecuritySignals) o;
        return Double.compare(that.provenanceTrustScore, provenanceTrustScore) == 0 &&
               Double.compare(that.sourceReliabilityScore, sourceReliabilityScore) == 0 &&
               Double.compare(that.contextConsistencyScore, contextConsistencyScore) == 0 &&
               Double.compare(that.provenanceCompletenessScore, provenanceCompletenessScore) == 0 &&
               Double.compare(that.sensitivityScore, sensitivityScore) == 0 &&
               Double.compare(that.anomalyScore, anomalyScore) == 0 &&
               Double.compare(that.instructionLikeScore, instructionLikeScore) == 0 &&
               Double.compare(that.privilegeRiskScore, privilegeRiskScore) == 0 &&
               Double.compare(that.temporalAnomalyScore, temporalAnomalyScore) == 0 &&
               Objects.equals(memoryId, that.memoryId) &&
               Objects.equals(correlationId, that.correlationId) &&
               Objects.equals(indicators, that.indicators) &&
               Objects.equals(analysisMetadata, that.analysisMetadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(memoryId, correlationId, provenanceTrustScore, sourceReliabilityScore,
                contextConsistencyScore, provenanceCompletenessScore, sensitivityScore, anomalyScore,
                instructionLikeScore, privilegeRiskScore, temporalAnomalyScore, indicators, analysisMetadata);
    }

    @Override
    public String toString() {
        return "SecuritySignals{" +
                "memoryId=" + memoryId +
                ", correlationId='" + correlationId + '\'' +
                ", provenanceTrustScore=" + provenanceTrustScore +
                ", sourceReliabilityScore=" + sourceReliabilityScore +
                ", contextConsistencyScore=" + contextConsistencyScore +
                ", provenanceCompletenessScore=" + provenanceCompletenessScore +
                ", sensitivityScore=" + sensitivityScore +
                ", anomalyScore=" + anomalyScore +
                ", instructionLikeScore=" + instructionLikeScore +
                ", privilegeRiskScore=" + privilegeRiskScore +
                ", temporalAnomalyScore=" + temporalAnomalyScore +
                ", indicatorCount=" + indicators.size() +
                '}';
    }
}

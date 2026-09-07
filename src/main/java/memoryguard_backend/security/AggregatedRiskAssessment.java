package memoryguard_backend.security;

import java.util.List;
import java.util.Map;

/**
 * Multi-dimensional security risk assessment result representing aggregated evidence.
 */
public class AggregatedRiskAssessment {

    private final int overallRiskScore;
    private final String overallRiskLevel;
    private final double confidence;
    private final String primaryCategory;
    private final String primaryReason;
    private final String dominantAnalyzerType;
    private final Map<String, Integer> dimensionalScores;
    private final List<String> detectedSignals;

    public AggregatedRiskAssessment(
            int overallRiskScore,
            String overallRiskLevel,
            double confidence,
            String primaryCategory,
            String primaryReason,
            String dominantAnalyzerType,
            Map<String, Integer> dimensionalScores,
            List<String> detectedSignals) {

        this.overallRiskScore = Math.min(100, Math.max(0, overallRiskScore));
        this.overallRiskLevel = overallRiskLevel;
        this.confidence = confidence;
        this.primaryCategory = primaryCategory != null ? primaryCategory : "UNKNOWN";
        this.primaryReason = primaryReason != null ? primaryReason : "";
        this.dominantAnalyzerType = dominantAnalyzerType != null ? dominantAnalyzerType : "MULTI_SIGNAL_PIPELINE";
        this.dimensionalScores = dimensionalScores != null ? dimensionalScores : Map.of();
        this.detectedSignals = detectedSignals != null ? detectedSignals : List.of();
    }

    public int getOverallRiskScore() {
        return overallRiskScore;
    }

    public String getOverallRiskLevel() {
        return overallRiskLevel;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getPrimaryCategory() {
        return primaryCategory;
    }

    public String getPrimaryReason() {
        return primaryReason;
    }

    public String getDominantAnalyzerType() {
        return dominantAnalyzerType;
    }

    public Map<String, Integer> getDimensionalScores() {
        return dimensionalScores;
    }

    public List<String> getDetectedSignals() {
        return detectedSignals;
    }
}

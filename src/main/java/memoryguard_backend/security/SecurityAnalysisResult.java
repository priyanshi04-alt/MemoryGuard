package memoryguard_backend.security;

public class SecurityAnalysisResult {

    private final String riskLevel;
    private final int riskScore;
    private final String category;
    private final String reason;
    private final double confidence;
    private final String analyzerType;

    public SecurityAnalysisResult(
            String riskLevel,
            int riskScore,
            String category,
            String reason,
            double confidence,
            String analyzerType) {

        this.riskLevel = riskLevel;
        this.riskScore = riskScore;
        this.category = category;
        this.reason = reason;
        this.confidence = confidence;
        this.analyzerType = analyzerType;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public String getCategory() {
        return category;
    }

    public String getReason() {
        return reason;
    }

    public double getConfidence() {
        return confidence;
    }

    public String getAnalyzerType() {
        return analyzerType;
    }
}
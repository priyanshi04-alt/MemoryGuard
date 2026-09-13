package memoryguard_backend.dto;

public class CalibrationRecommendation {

    private String patternDetected;
    private long sampleCount;
    private String relevantRiskPattern;
    private double confidenceScore;
    private String suggestedDirection;
    private String explanation;

    public CalibrationRecommendation() {
    }

    public CalibrationRecommendation(String patternDetected, long sampleCount, String relevantRiskPattern,
                                     double confidenceScore, String suggestedDirection, String explanation) {
        this.patternDetected = patternDetected;
        this.sampleCount = sampleCount;
        this.relevantRiskPattern = relevantRiskPattern;
        this.confidenceScore = confidenceScore;
        this.suggestedDirection = suggestedDirection;
        this.explanation = explanation;
    }

    public String getPatternDetected() {
        return patternDetected;
    }

    public void setPatternDetected(String patternDetected) {
        this.patternDetected = patternDetected;
    }

    public long getSampleCount() {
        return sampleCount;
    }

    public void setSampleCount(long sampleCount) {
        this.sampleCount = sampleCount;
    }

    public String getRelevantRiskPattern() {
        return relevantRiskPattern;
    }

    public void setRelevantRiskPattern(String relevantRiskPattern) {
        this.relevantRiskPattern = relevantRiskPattern;
    }

    public double getConfidenceScore() {
        return confidenceScore;
    }

    public void setConfidenceScore(double confidenceScore) {
        this.confidenceScore = confidenceScore;
    }

    public String getSuggestedDirection() {
        return suggestedDirection;
    }

    public void setSuggestedDirection(String suggestedDirection) {
        this.suggestedDirection = suggestedDirection;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }
}

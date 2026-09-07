package memoryguard_backend.security.context;

import java.util.List;

public class ContextAnalysisResult {

    private final String riskLevel;
    private final int riskScore;
    private final String category;
    private final String reason;
    private final List<String> conflicts;

    public ContextAnalysisResult(String riskLevel, int riskScore, String category, String reason, List<String> conflicts) {
        this.riskLevel = riskLevel;
        this.riskScore = riskScore;
        this.category = category;
        this.reason = reason;
        this.conflicts = conflicts != null ? conflicts : List.of();
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

    public List<String> getConflicts() {
        return conflicts;
    }
}

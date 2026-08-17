package memoryguard_backend.security;

import java.util.List;

public class RuleAnalysisResult {

    private final int riskScore;
    private final List<String> threats;
    private final List<String> reasons;

    public RuleAnalysisResult(
            int riskScore,
            List<String> threats,
            List<String> reasons) {

        this.riskScore = riskScore;
        this.threats = threats;
        this.reasons = reasons;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public List<String> getThreats() {
        return threats;
    }

    public List<String> getReasons() {
        return reasons;
    }
}
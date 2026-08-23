package memoryguard_backend.security;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RiskAggregator {

    public SecurityAnalysisResult aggregate(
            List<SecurityAnalysisResult> results) {

        if (results == null || results.isEmpty()) {
            return new SecurityAnalysisResult(
                    "LOW",
                    0,
                    "NO_ANALYSIS",
                    "No security analysis results available",
                    0.0,
                    "AGGREGATED"
            );
        }

        // Filter out unavailable semantic results
        List<SecurityAnalysisResult> activeResults = new java.util.ArrayList<>();
        for (SecurityAnalysisResult result : results) {
            if (result != null && !"SEMANTIC_UNAVAILABLE".equals(result.getCategory())) {
                activeResults.add(result);
            }
        }

        if (activeResults.isEmpty()) {
            // Fallback: If all results are unavailable, return the first one
            SecurityAnalysisResult fallback = results.get(0);
            return new SecurityAnalysisResult(
                    fallback.getRiskLevel(),
                    fallback.getRiskScore(),
                    fallback.getCategory(),
                    fallback.getReason(),
                    fallback.getConfidence(),
                    "AGGREGATED"
            );
        }

        // Apply safety-first maximum-score strategy
        SecurityAnalysisResult highestRiskResult = activeResults.get(0);
        int highestRiskScore = highestRiskResult.getRiskScore();

        for (int i = 1; i < activeResults.size(); i++) {
            SecurityAnalysisResult result = activeResults.get(i);
            if (result.getRiskScore() > highestRiskScore) {
                highestRiskScore = result.getRiskScore();
                highestRiskResult = result;
            }
        }

        return new SecurityAnalysisResult(
                getRiskLevel(highestRiskScore),
                highestRiskScore,
                highestRiskResult.getCategory(),
                highestRiskResult.getReason(),
                highestRiskResult.getConfidence(),
                "AGGREGATED"
        );
    }

    private String getRiskLevel(int score) {

        if (score >= 80) {
            return "HIGH";
        }

        if (score >= 50) {
            return "MEDIUM";
        }

        return "LOW";
    }
}
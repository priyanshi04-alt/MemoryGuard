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
                    "AGGREGATOR"
            );
        }

        int highestRiskScore = 0;
        SecurityAnalysisResult highestRiskResult = null;

        for (SecurityAnalysisResult result : results) {

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
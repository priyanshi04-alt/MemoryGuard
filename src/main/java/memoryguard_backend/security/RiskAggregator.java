package memoryguard_backend.security;

import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class RiskAggregator {

    public SecurityAnalysisResult aggregate(List<SecurityAnalysisResult> results) {
        AggregatedRiskAssessment assessment = aggregateAssessment(results);
        return new SecurityAnalysisResult(
                assessment.getOverallRiskLevel(),
                assessment.getOverallRiskScore(),
                assessment.getPrimaryCategory(),
                assessment.getPrimaryReason(),
                assessment.getConfidence(),
                assessment.getDominantAnalyzerType()
        );
    }

    public AggregatedRiskAssessment aggregateAssessment(List<SecurityAnalysisResult> results) {
        if (results == null || results.isEmpty()) {
            return new AggregatedRiskAssessment(
                    0,
                    "LOW",
                    1.0,
                    "NO_ANALYSIS",
                    "No security analysis results available",
                    "AGGREGATED",
                    Map.of("provenance", 0, "injection", 0, "sensitivity", 0, "context", 0),
                    List.of()
            );
        }

        Map<String, Integer> dimensions = new LinkedHashMap<>();
        dimensions.put("provenanceRisk", 0);
        dimensions.put("injectionRisk", 0);
        dimensions.put("sensitivityRisk", 0);
        dimensions.put("threatRisk", 0);
        dimensions.put("contextRisk", 0);

        List<String> signalsList = new ArrayList<>();
        SecurityAnalysisResult dominantResult = null;
        int maxBaseScore = -1;
        double maxConfidence = 0.0;
        int activeSignalsCount = 0;

        for (SecurityAnalysisResult res : results) {
            if (res == null || "SEMANTIC_UNAVAILABLE".equals(res.getCategory())) {
                continue;
            }

            int score = res.getRiskScore();
            String cat = res.getCategory();
            String type = res.getAnalyzerType() != null ? res.getAnalyzerType() : "UNKNOWN";

            // Map categories to risk dimensions
            if (cat.startsWith("PROVENANCE_")) {
                dimensions.put("provenanceRisk", Math.max(dimensions.get("provenanceRisk"), score));
            } else if (cat.contains("INJECTION") || cat.contains("OVERRIDE")) {
                dimensions.put("injectionRisk", Math.max(dimensions.get("injectionRisk"), score));
            } else if (cat.contains("CREDENTIAL") || cat.contains("SECRET")) {
                dimensions.put("sensitivityRisk", Math.max(dimensions.get("sensitivityRisk"), score));
            } else if (cat.contains("CONTEXT")) {
                dimensions.put("contextRisk", Math.max(dimensions.get("contextRisk"), score));
            } else {
                dimensions.put("threatRisk", Math.max(dimensions.get("threatRisk"), score));
            }

            if (score > 15 && !"BENIGN_SECURITY_CONTENT".equals(cat) && !"NO_MAJOR_RISK".equals(cat)) {
                activeSignalsCount++;
                signalsList.add(type + ": [" + cat + "] " + res.getReason());
            }

            if (dominantResult == null || score > maxBaseScore) {
                maxBaseScore = score;
                dominantResult = res;
                maxConfidence = res.getConfidence();
            }
        }

        if (dominantResult == null) {
            dominantResult = results.get(0);
            maxBaseScore = dominantResult.getRiskScore();
            maxConfidence = dominantResult.getConfidence();
        }

        // Multi-signal risk accumulation: apply boost when multiple weak/medium signals (score < 80) combine
        int finalScore = maxBaseScore;
        boolean isBenign = "BENIGN_SECURITY_CONTENT".equals(dominantResult.getCategory()) || "NO_MAJOR_RISK".equals(dominantResult.getCategory());
        
        if (!isBenign && activeSignalsCount > 1 && maxBaseScore >= 35 && maxBaseScore < 80) {
            int accumulationBoost = (activeSignalsCount - 1) * 10;
            finalScore = Math.min(79, maxBaseScore + accumulationBoost);
        }

        String finalLevel = getRiskLevel(finalScore);
        String dominantAnalyzerType = dominantResult.getAnalyzerType() != null ? dominantResult.getAnalyzerType() : "MULTI_SIGNAL_PIPELINE";
        
        // Build explainable synthesis
        String synthesizedReason;
        if (signalsList.isEmpty()) {
            synthesizedReason = dominantResult.getReason() != null ? dominantResult.getReason() : "No security threat detected";
        } else if (signalsList.size() == 1) {
            synthesizedReason = dominantResult.getReason();
        } else {
            synthesizedReason = "Multiple security signals detected (" + activeSignalsCount + "): " + String.join(" | ", signalsList);
        }

        return new AggregatedRiskAssessment(
                finalScore,
                finalLevel,
                maxConfidence,
                dominantResult.getCategory(),
                synthesizedReason,
                dominantAnalyzerType,
                dimensions,
                signalsList
        );
    }

    public String getRiskLevel(int score) {
        if (score >= 80) {
            return "HIGH";
        }
        if (score >= 50) {
            return "MEDIUM";
        }
        return "LOW";
    }
}
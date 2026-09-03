package memoryguard_backend.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents the structured result of an AI semantic security analysis execution.
 * Extends SecurityAnalysisResult so it seamlessly integrates into RiskAggregator,
 * PolicyEngine, and SecurityLog audit history while providing detailed semantic evidence.
 */
public class SemanticAnalysisResult extends SecurityAnalysisResult {

    private final boolean performed;
    private final List<SemanticSecuritySignal> signals;
    private final String analyzerVersion;
    private final Map<String, Object> analysisMetadata;

    public SemanticAnalysisResult(
            boolean performed,
            String riskLevel,
            int riskScore,
            String category,
            String reason,
            double confidence,
            List<SemanticSecuritySignal> signals,
            String analyzerType,
            String analyzerVersion,
            Map<String, Object> analysisMetadata) {

        super(
                riskLevel,
                riskScore,
                category,
                reason,
                confidence,
                analyzerType != null ? analyzerType : "SEMANTIC"
        );

        this.performed = performed;
        this.signals = signals != null ? Collections.unmodifiableList(new ArrayList<>(signals)) : Collections.emptyList();
        this.analyzerVersion = analyzerVersion != null ? analyzerVersion : "1.0.0";
        this.analysisMetadata = analysisMetadata != null ? Collections.unmodifiableMap(new HashMap<>(analysisMetadata)) : Collections.emptyMap();
    }

    public SemanticAnalysisResult(
            boolean performed,
            String riskLevel,
            int riskScore,
            String category,
            String reason,
            double confidence,
            List<SemanticSecuritySignal> signals) {

        this(performed, riskLevel, riskScore, category, reason, confidence, signals, "SEMANTIC", "1.0.0", Collections.emptyMap());
    }

    /**
     * Factory method for creating an unperformed or unavailable semantic result.
     */
    public static SemanticAnalysisResult unavailable(String reason) {
        return new SemanticAnalysisResult(
                false,
                "LOW",
                0,
                "SEMANTIC_UNAVAILABLE",
                reason,
                0.0,
                Collections.emptyList(),
                "SEMANTIC",
                "1.0.0",
                Collections.emptyMap()
        );
    }

    /**
     * Factory method for creating a result when input is empty or blank.
     */
    public static SemanticAnalysisResult emptyContent() {
        return new SemanticAnalysisResult(
                true,
                "LOW",
                0,
                "EMPTY_CONTENT",
                "Input content is null or blank",
                1.0,
                Collections.emptyList(),
                "SEMANTIC",
                "1.0.0",
                Collections.emptyMap()
        );
    }

    public boolean isPerformed() {
        return performed;
    }

    public List<SemanticSecuritySignal> getSignals() {
        return signals;
    }

    public String getAnalyzerVersion() {
        return analyzerVersion;
    }

    public Map<String, Object> getAnalysisMetadata() {
        return analysisMetadata;
    }
}

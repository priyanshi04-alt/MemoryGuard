package memoryguard_backend.security;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.security.signals.SecuritySignals;

import java.util.Collections;

/**
 * Interface abstraction for semantic security analysis.
 * Decouples the domain layer from specific model implementations (e.g. baseline rule analyzer, local ML model, LLM provider).
 */
public interface SemanticSecurityAnalyzer extends SecurityAnalyzer {

    @Override
    SecurityAnalysisResult analyze(String content);

    /**
     * Helper method to obtain a guaranteed SemanticAnalysisResult.
     */
    default SemanticAnalysisResult analyzeSemantic(String content) {
        SecurityAnalysisResult result = analyze(content);
        if (result instanceof SemanticAnalysisResult) {
            return (SemanticAnalysisResult) result;
        }
        if (result == null) {
            return SemanticAnalysisResult.emptyContent();
        }
        return new SemanticAnalysisResult(
                true,
                result.getRiskLevel(),
                result.getRiskScore(),
                result.getCategory(),
                result.getReason(),
                result.getConfidence(),
                Collections.emptyList(),
                result.getAnalyzerType(),
                "1.0.0",
                Collections.emptyMap()
        );
    }

    /**
     * Contextual semantic evaluation accepting Memory entity and extracted security signals.
     */
    default SemanticAnalysisResult analyzeSemantic(Memory memory, SecuritySignals signals) {
        if (memory == null) {
            return analyzeSemantic((String) null);
        }
        return analyzeSemantic(memory.getContent());
    }

    @Override
    default String getAnalyzerType() {
        return "SEMANTIC";
    }
}

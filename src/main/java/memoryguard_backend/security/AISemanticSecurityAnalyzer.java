package memoryguard_backend.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.Collections;

/**
 * Primary semantic security analyzer bean.
 * Bridges external AI services (e.g. GeminiAIService) with the provider-agnostic
 * SemanticSecurityAnalyzer interface and fallbacks to BaselineSemanticAnalyzer.
 */
@Component
@Primary
public class AISemanticSecurityAnalyzer implements SemanticSecurityAnalyzer {

    private final AIService aiService;
    private final AiConfigProperties aiConfigProperties;
    private final BaselineSemanticAnalyzer baselineAnalyzer;

    @Autowired
    public AISemanticSecurityAnalyzer(
            AIService aiService,
            AiConfigProperties aiConfigProperties,
            BaselineSemanticAnalyzer baselineAnalyzer) {

        this.aiService = aiService;
        this.aiConfigProperties = aiConfigProperties;
        this.baselineAnalyzer = baselineAnalyzer != null ? baselineAnalyzer : new BaselineSemanticAnalyzer();
    }

    public AISemanticSecurityAnalyzer(AIService aiService, AiConfigProperties aiConfigProperties) {
        this(aiService, aiConfigProperties, new BaselineSemanticAnalyzer());
    }

    @Override
    public String getAnalyzerType() {
        return "SEMANTIC";
    }

    @Override
    public SecurityAnalysisResult analyze(String content) {
        // 1. Check if AI is disabled
        if (!aiConfigProperties.isEnabled()) {
            return SemanticAnalysisResult.unavailable("AI Semantic Analysis is disabled");
        }

        // 2. Null or blank content checks
        if (content == null || content.trim().isEmpty()) {
            return SemanticAnalysisResult.emptyContent();
        }

        // 3. Evaluate content through AIService with fail-safe boundaries
        try {
            SecurityAnalysisResult baseResult = aiService.evaluate(content);
            if (baseResult instanceof SemanticAnalysisResult) {
                return baseResult;
            }
            return new SemanticAnalysisResult(
                    true,
                    baseResult.getRiskLevel(),
                    baseResult.getRiskScore(),
                    baseResult.getCategory(),
                    baseResult.getReason(),
                    baseResult.getConfidence(),
                    Collections.emptyList(),
                    baseResult.getAnalyzerType(),
                    "1.0.0",
                    Collections.emptyMap()
            );
        } catch (AIServiceException e) {
            return SemanticAnalysisResult.unavailable("Semantic analysis is currently unavailable");
        } catch (Exception e) {
            return SemanticAnalysisResult.unavailable("Semantic analysis encountered an unexpected error");
        }
    }

    public BaselineSemanticAnalyzer getBaselineAnalyzer() {
        return baselineAnalyzer;
    }
}

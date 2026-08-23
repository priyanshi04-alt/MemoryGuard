package memoryguard_backend.security;

import org.springframework.stereotype.Component;

@Component
public class AISemanticSecurityAnalyzer implements SecurityAnalyzer {

    private final AIService aiService;
    private final AiConfigProperties aiConfigProperties;

    public AISemanticSecurityAnalyzer(AIService aiService, AiConfigProperties aiConfigProperties) {
        this.aiService = aiService;
        this.aiConfigProperties = aiConfigProperties;
    }

    @Override
    public String getAnalyzerType() {
        return "SEMANTIC";
    }

    @Override
    public SecurityAnalysisResult analyze(String content) {
        // 1. Check if AI is disabled
        if (!aiConfigProperties.isEnabled()) {
            return createUnavailableResult("AI Semantic Analysis is disabled");
        }

        // 2. Null or blank content checks
        if (content == null || content.trim().isEmpty()) {
            return new SecurityAnalysisResult(
                    "LOW",
                    0,
                    "EMPTY_CONTENT",
                    "Input content is null or blank",
                    1.0,
                    "SEMANTIC"
            );
        }

        // 3. Evaluate content through AIService with fail-safe boundaries
        try {
            return aiService.evaluate(content);
        } catch (AIServiceException e) {
            return createUnavailableResult("Semantic analysis is currently unavailable");
        } catch (Exception e) {
            return createUnavailableResult("Semantic analysis encountered an unexpected error");
        }
    }

    private SecurityAnalysisResult createUnavailableResult(String reason) {
        return new SecurityAnalysisResult(
                "LOW",
                0,
                "SEMANTIC_UNAVAILABLE",
                reason,
                0.0,
                "SEMANTIC"
        );
    }
}

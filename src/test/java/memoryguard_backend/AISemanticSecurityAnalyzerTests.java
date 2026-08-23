package memoryguard_backend;

import memoryguard_backend.security.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AISemanticSecurityAnalyzerTests {

    private AIService aiService;
    private AiConfigProperties aiConfigProperties;
    private AISemanticSecurityAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        aiService = mock(AIService.class);
        aiConfigProperties = new AiConfigProperties();
        aiConfigProperties.setEnabled(true);
        analyzer = new AISemanticSecurityAnalyzer(aiService, aiConfigProperties);
    }

    @Test
    void successfulHighSemanticResult() {
        SecurityAnalysisResult mockResult = new SecurityAnalysisResult("HIGH", 85, "PROMPT_INJECTION", "Attacks detected", 0.95, "SEMANTIC");
        when(aiService.evaluate("Injection content")).thenReturn(mockResult);

        SecurityAnalysisResult result = analyzer.analyze("Injection content");
        assertNotNull(result);
        assertEquals("HIGH", result.getRiskLevel());
        assertEquals(85, result.getRiskScore());
        assertEquals("PROMPT_INJECTION", result.getCategory());
        assertEquals(0.95, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
    }

    @Test
    void successfulMediumSemanticResult() {
        SecurityAnalysisResult mockResult = new SecurityAnalysisResult("MEDIUM", 55, "CREDENTIAL_REFERENCE", "Mentions API keys", 0.85, "SEMANTIC");
        when(aiService.evaluate("Secret context")).thenReturn(mockResult);

        SecurityAnalysisResult result = analyzer.analyze("Secret context");
        assertNotNull(result);
        assertEquals("MEDIUM", result.getRiskLevel());
        assertEquals(55, result.getRiskScore());
        assertEquals("CREDENTIAL_REFERENCE", result.getCategory());
        assertEquals(0.85, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
    }

    @Test
    void successfulLowSemanticResult() {
        SecurityAnalysisResult mockResult = new SecurityAnalysisResult("LOW", 10, "NONE", "Normal talk", 0.99, "SEMANTIC");
        when(aiService.evaluate("Normal talk")).thenReturn(mockResult);

        SecurityAnalysisResult result = analyzer.analyze("Normal talk");
        assertNotNull(result);
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(10, result.getRiskScore());
        assertEquals("NONE", result.getCategory());
        assertEquals(0.99, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
    }

    @Test
    void aiServiceTimeoutFailure() {
        when(aiService.evaluate(anyString())).thenThrow(new AIServiceException(AIServiceException.FailureType.TIMEOUT, "Timeout occurred"));

        SecurityAnalysisResult result = analyzer.analyze("Timeout content");
        assertNotNull(result);
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(0, result.getRiskScore());
        assertEquals("SEMANTIC_UNAVAILABLE", result.getCategory());
        assertEquals(0.0, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
        assertFalse(result.getReason().contains("Timeout occurred"));
    }

    @Test
    void aiServiceMalformedResponseFailure() {
        when(aiService.evaluate(anyString())).thenThrow(new AIServiceException(AIServiceException.FailureType.MALFORMED_RESPONSE, "Malformed JSON"));

        SecurityAnalysisResult result = analyzer.analyze("Malformed content");
        assertNotNull(result);
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(0, result.getRiskScore());
        assertEquals("SEMANTIC_UNAVAILABLE", result.getCategory());
        assertEquals(0.0, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
        assertFalse(result.getReason().contains("Malformed JSON"));
    }

    @Test
    void aiServiceHttpFailure() {
        when(aiService.evaluate(anyString())).thenThrow(new AIServiceException(AIServiceException.FailureType.HTTP_ERROR, "HTTP 500 error"));

        SecurityAnalysisResult result = analyzer.analyze("HTTP error content");
        assertNotNull(result);
        assertEquals("LOW", result.getRiskLevel());
        assertEquals("SEMANTIC_UNAVAILABLE", result.getCategory());
        assertEquals(0.0, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
        assertFalse(result.getReason().contains("HTTP 500"));
    }

    @Test
    void nullInputReturnsEmptyContentResult() {
        SecurityAnalysisResult result = analyzer.analyze(null);
        assertNotNull(result);
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(0, result.getRiskScore());
        assertEquals("EMPTY_CONTENT", result.getCategory());
        assertEquals(1.0, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
        verify(aiService, never()).evaluate(anyString());
    }

    @Test
    void blankInputReturnsEmptyContentResult() {
        SecurityAnalysisResult result = analyzer.analyze("   ");
        assertNotNull(result);
        assertEquals("LOW", result.getRiskLevel());
        assertEquals("EMPTY_CONTENT", result.getCategory());
        assertEquals(1.0, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
        verify(aiService, never()).evaluate(anyString());
    }

    @Test
    void aiDisabledReturnsUnavailableResult() {
        aiConfigProperties.setEnabled(false);
        SecurityAnalysisResult result = analyzer.analyze("Some text");
        assertNotNull(result);
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(0, result.getRiskScore());
        assertEquals("SEMANTIC_UNAVAILABLE", result.getCategory());
        assertEquals(0.0, result.getConfidence());
        assertEquals("AI Semantic Analysis is disabled", result.getReason());
        verify(aiService, never()).evaluate(anyString());
    }

    @Test
    void sensitiveDataLeakProtection() {
        String sensitiveKey = "API_KEY_SECRET_123";
        String sensitiveMemory = "This is a super secret memory payload";
        when(aiService.evaluate(anyString())).thenThrow(
                new AIServiceException(AIServiceException.FailureType.HTTP_ERROR, "Failed to connect using key " + sensitiveKey + " with payload " + sensitiveMemory)
        );

        SecurityAnalysisResult result = analyzer.analyze(sensitiveMemory);
        assertNotNull(result);
        assertEquals("SEMANTIC_UNAVAILABLE", result.getCategory());
        assertFalse(result.getReason().contains(sensitiveKey));
        assertFalse(result.getReason().contains(sensitiveMemory));
    }
}

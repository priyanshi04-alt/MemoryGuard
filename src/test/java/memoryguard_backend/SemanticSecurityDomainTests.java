package memoryguard_backend;

import memoryguard_backend.security.SemanticAnalysisResult;
import memoryguard_backend.security.SemanticSecuritySignal;
import memoryguard_backend.security.SemanticSignalType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SemanticSecurityDomainTests {

    @Test
    @DisplayName("Verify SemanticSignalType enum values, descriptions, and default risk weights")
    void testSemanticSignalTypeEnum() {
        assertEquals(10, SemanticSignalType.values().length);

        SemanticSignalType injection = SemanticSignalType.PROMPT_INJECTION;
        assertEquals("PROMPT_INJECTION", injection.name());
        assertEquals(85, injection.getDefaultRiskWeight());
        assertNotNull(injection.getDescription());

        SemanticSignalType benign = SemanticSignalType.BENIGN_SECURITY_CONTENT;
        assertEquals(5, benign.getDefaultRiskWeight());
    }

    @Test
    @DisplayName("Verify SemanticSecuritySignal creation, boundary clamping, and getters")
    void testSemanticSecuritySignalModel() {
        SemanticSecuritySignal signal = new SemanticSecuritySignal(
                SemanticSignalType.PROMPT_INJECTION,
                85,
                0.95,
                "Prompt injection phrase detected",
                "ignore previous instructions",
                "test-detector"
        );

        assertEquals(SemanticSignalType.PROMPT_INJECTION, signal.getSignalType());
        assertEquals(85, signal.getRiskContribution());
        assertEquals(0.95, signal.getConfidence());
        assertEquals("Prompt injection phrase detected", signal.getEvidence());
        assertEquals("ignore previous instructions", signal.getSnippet());
        assertEquals("test-detector", signal.getSource());
    }

    @Test
    @DisplayName("Verify SemanticSecuritySignal risk contribution clamping to [0, 100]")
    void testSignalRiskContributionClamping() {
        SemanticSecuritySignal overClamped = new SemanticSecuritySignal(
                SemanticSignalType.SECRET_EXFILTRATION, 150, 1.2, "Excess score"
        );
        assertEquals(100, overClamped.getRiskContribution());
        assertEquals(1.0, overClamped.getConfidence());

        SemanticSecuritySignal underClamped = new SemanticSecuritySignal(
                SemanticSignalType.BENIGN_SECURITY_CONTENT, -20, -0.5, "Negative score"
        );
        assertEquals(0, underClamped.getRiskContribution());
        assertEquals(0.0, underClamped.getConfidence());
    }

    @Test
    @DisplayName("Verify SemanticAnalysisResult inherits SecurityAnalysisResult and provides structured signals")
    void testSemanticAnalysisResultStructure() {
        SemanticSecuritySignal signal = new SemanticSecuritySignal(
                SemanticSignalType.PRIVILEGE_ESCALATION, 85, 0.90, "Privilege escalation attempt"
        );

        SemanticAnalysisResult result = new SemanticAnalysisResult(
                true,
                "HIGH",
                85,
                "PRIVILEGE_ESCALATION",
                "Privilege escalation attempt",
                0.90,
                List.of(signal)
        );

        assertTrue(result.isPerformed());
        assertEquals("HIGH", result.getRiskLevel());
        assertEquals(85, result.getRiskScore());
        assertEquals("PRIVILEGE_ESCALATION", result.getCategory());
        assertEquals("Privilege escalation attempt", result.getReason());
        assertEquals(0.90, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
        assertEquals(1, result.getSignals().size());
        assertEquals(signal, result.getSignals().get(0));
    }

    @Test
    @DisplayName("Verify SemanticAnalysisResult factory methods")
    void testSemanticAnalysisResultFactoryMethods() {
        SemanticAnalysisResult unavailable = SemanticAnalysisResult.unavailable("Service disabled");
        assertFalse(unavailable.isPerformed());
        assertEquals("LOW", unavailable.getRiskLevel());
        assertEquals(0, unavailable.getRiskScore());
        assertEquals("SEMANTIC_UNAVAILABLE", unavailable.getCategory());
        assertEquals(0.0, unavailable.getConfidence());

        SemanticAnalysisResult empty = SemanticAnalysisResult.emptyContent();
        assertTrue(empty.isPerformed());
        assertEquals("EMPTY_CONTENT", empty.getCategory());
        assertEquals(1.0, empty.getConfidence());
    }
}

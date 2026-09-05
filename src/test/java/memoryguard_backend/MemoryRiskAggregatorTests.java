package memoryguard_backend;

import memoryguard_backend.security.content.ContentAnalysisResult;
import memoryguard_backend.security.content.ContentSecuritySignal;
import memoryguard_backend.security.risk.AggregatedSignalContribution;
import memoryguard_backend.security.risk.MemoryRiskAggregator;
import memoryguard_backend.security.risk.MemoryRiskAssessment;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MemoryRiskAggregatorTests {

    private MemoryRiskAggregator riskAggregator;

    @BeforeEach
    void setUp() {
        riskAggregator = new MemoryRiskAggregator();
    }

    @Test
    @DisplayName("Test 1 — No Signals: Returns zero risk, LOW level, empty signals list")
    void test1_NoSignals_ReturnsZeroRiskAndLowLevel() {
        // Given an empty list of signals
        List<ContentSecuritySignal> signals = new ArrayList<>();

        // When aggregated
        MemoryRiskAssessment assessment = riskAggregator.aggregate(signals);

        // Then
        assertNotNull(assessment);
        assertEquals(0, assessment.getRiskScore());
        assertEquals("LOW", assessment.getRiskLevel());
        assertEquals(0, assessment.getSignalCount());
        assertTrue(assessment.getSignals().isEmpty());

        // Test with null ContentAnalysisResult
        MemoryRiskAssessment nullResultAssessment = riskAggregator.aggregate((ContentAnalysisResult) null);
        assertNotNull(nullResultAssessment);
        assertEquals(0, nullResultAssessment.getRiskScore());
        assertEquals("LOW", nullResultAssessment.getRiskLevel());
        assertEquals(0, nullResultAssessment.getSignalCount());
    }

    @Test
    @DisplayName("Test 2 — Single Medium Signal: Returns non-zero risk matching scoring thresholds")
    void test2_SingleMediumSignal_ReturnsCorrectRiskScore() {
        // Given single MEDIUM severity signal
        List<ContentSecuritySignal> signals = List.of(
                new ContentSecuritySignal("POLICY_OVERRIDE_ATTEMPT", "MEDIUM", "Policy override attempt detected")
        );

        // When aggregated
        MemoryRiskAssessment assessment = riskAggregator.aggregate(signals);

        // Then
        assertNotNull(assessment);
        assertEquals(50, assessment.getRiskScore());
        assertEquals("HIGH", assessment.getRiskLevel()); // 50-74 threshold maps to HIGH
        assertEquals(1, assessment.getSignalCount());
        assertEquals(1, assessment.getSignals().size());

        AggregatedSignalContribution contrib = assessment.getSignals().get(0);
        assertEquals("POLICY_OVERRIDE_ATTEMPT", contrib.getType());
        assertEquals("MEDIUM", contrib.getSeverity());
        assertEquals(50, contrib.getContribution());
    }

    @Test
    @DisplayName("Test 3 — Single High Signal: Returns high risk contribution and correct risk level")
    void test3_SingleHighSignal_ReturnsHighRiskAndCorrectLevel() {
        // Given single HIGH severity signal
        List<ContentSecuritySignal> signals = List.of(
                new ContentSecuritySignal("PROMPT_INJECTION", "HIGH", "Instruction override pattern")
        );

        // When aggregated
        MemoryRiskAssessment assessment = riskAggregator.aggregate(signals);

        // Then
        assertNotNull(assessment);
        assertEquals(80, assessment.getRiskScore());
        assertEquals("CRITICAL", assessment.getRiskLevel()); // 75-100 maps to CRITICAL
        assertEquals(1, assessment.getSignalCount());

        AggregatedSignalContribution contrib = assessment.getSignals().get(0);
        assertEquals("PROMPT_INJECTION", contrib.getType());
        assertEquals("HIGH", contrib.getSeverity());
        assertEquals(80, contrib.getContribution());
    }

    @Test
    @DisplayName("Test 4 — Multiple Signals: Calculates combined score reflecting evidence capped at 100")
    void test4_MultipleHighSignals_CalculatesCombinedScore() {
        // Given multiple HIGH severity signals
        List<ContentSecuritySignal> signals = List.of(
                new ContentSecuritySignal("PROMPT_INJECTION", "HIGH", "Instruction override pattern"),
                new ContentSecuritySignal("SYSTEM_PROMPT_EXTRACTION", "HIGH", "Hidden prompt extraction attempt")
        );

        // When aggregated
        MemoryRiskAssessment assessment = riskAggregator.aggregate(signals);

        // Then
        assertNotNull(assessment);
        assertEquals(90, assessment.getRiskScore()); // 80 + 10 increment = 90
        assertEquals("CRITICAL", assessment.getRiskLevel());
        assertEquals(2, assessment.getSignalCount());
        assertEquals(2, assessment.getSignals().size());
        assertTrue(assessment.getRiskScore() <= 100);
    }

    @Test
    @DisplayName("Test 5 — Mixed Severity: Strongest signal primary, additional evidence reinforces score")
    void test5_MixedSeverity_StrongestSignalInfluencesScore() {
        // Given mixed HIGH and MEDIUM signals
        List<ContentSecuritySignal> signals = List.of(
                new ContentSecuritySignal("POLICY_OVERRIDE_ATTEMPT", "MEDIUM", "Policy override attempt"),
                new ContentSecuritySignal("PROMPT_INJECTION", "HIGH", "Instruction override pattern")
        );

        // When aggregated
        MemoryRiskAssessment assessment = riskAggregator.aggregate(signals);

        // Then: HIGH (80) is strongest primary, MEDIUM adds +5 boost -> total 85
        assertNotNull(assessment);
        assertEquals(85, assessment.getRiskScore());
        assertEquals("CRITICAL", assessment.getRiskLevel());
        assertEquals(2, assessment.getSignalCount());

        // First signal in contribution list is the primary strongest signal
        assertEquals("PROMPT_INJECTION", assessment.getSignals().get(0).getType());
        assertEquals(80, assessment.getSignals().get(0).getContribution());
        assertEquals(5, assessment.getSignals().get(1).getContribution());
    }

    @Test
    @DisplayName("Test 6 — Critical Signal: Produces maximum risk contribution")
    void test6_CriticalSignal_ProducesMaximumRiskContribution() {
        // Given CRITICAL severity signal
        List<ContentSecuritySignal> signals = List.of(
                new ContentSecuritySignal("SEVERE_THREAT", "CRITICAL", "Critical security violation")
        );

        // When aggregated
        MemoryRiskAssessment assessment = riskAggregator.aggregate(signals);

        // Then
        assertNotNull(assessment);
        assertEquals(100, assessment.getRiskScore());
        assertEquals("CRITICAL", assessment.getRiskLevel());
        assertEquals(1, assessment.getSignalCount());
        assertEquals(100, assessment.getSignals().get(0).getContribution());
    }

    @Test
    @DisplayName("Test 7 — No Policy Decision: Explicitly verifies Absence of Policy Decision fields")
    void test7_NoPolicyDecision_VerifiesAbsenceOfPolicyFields() {
        // Given an aggregated risk assessment
        List<ContentSecuritySignal> signals = List.of(
                new ContentSecuritySignal("PROMPT_INJECTION", "HIGH", "Instruction override pattern")
        );

        MemoryRiskAssessment assessment = riskAggregator.aggregate(signals);

        // Verify structure has risk fields
        assertNotNull(assessment.getRiskScore());
        assertNotNull(assessment.getRiskLevel());
        assertNotNull(assessment.getSignals());

        // Reflection test to strictly enforce architectural boundary:
        // MemoryRiskAssessment MUST NOT contain fields or methods returning ALLOW, BLOCK, or REVIEW decisions.
        Field[] fields = MemoryRiskAssessment.class.getDeclaredFields();
        for (Field field : fields) {
            String name = field.getName().toLowerCase();
            assertFalse(name.contains("policy"), "MemoryRiskAssessment should not contain policy fields: " + field.getName());
            assertFalse(name.contains("decision"), "MemoryRiskAssessment should not contain decision fields: " + field.getName());
            assertFalse(name.contains("action"), "MemoryRiskAssessment should not contain action fields: " + field.getName());
        }

        // Verify string representation does not contain policy decisions
        String strRepr = assessment.toString();
        assertFalse(strRepr.contains("ALLOW"));
        assertFalse(strRepr.contains("BLOCK"));
        assertFalse(strRepr.contains("REVIEW"));
    }
}

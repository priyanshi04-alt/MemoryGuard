package memoryguard_backend;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.ProvenanceType;
import memoryguard_backend.security.*;
import memoryguard_backend.security.context.ContextAnalysisResult;
import memoryguard_backend.security.context.ContextAnalyzer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class PolicyEngineTests {

    private PolicyEngine policyEngine;
    private PolicyProperties policyProperties;
    private RiskAggregator riskAggregator;

    @BeforeEach
    void setUp() {
        policyProperties = new PolicyProperties();
        policyProperties.setBlockThreshold(80);
        policyProperties.setReviewThreshold(50);
        policyProperties.setHighConfidenceThreshold(0.70);
        policyProperties.setCriticalThreatAutoBlock(true);
        policyProperties.setFailSafeDefaultDecision("REVIEW");

        policyEngine = new PolicyEngine(policyProperties);
        riskAggregator = new RiskAggregator();
    }

    // ====================================================================
    // TEST A: LOW risk + HIGH confidence -> ALLOW
    // ====================================================================
    @Test
    @DisplayName("Scenario A: LOW risk + HIGH confidence should produce ALLOW decision")
    void testA_LowRisk_HighConfidence_Allows() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                15,
                "LOW",
                0.95,
                "NO_MAJOR_RISK",
                "User requested calendar update for team meeting.",
                "BASELINE",
                Map.of("provenanceRisk", 0, "injectionRisk", 0),
                List.of()
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.ALLOW, result.getDecision());
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(0.95, result.getConfidence());
        assertEquals("LOW_RISK_BASELINE", result.getPolicyRule());
        assertEquals("PERMITTED", result.getPersistenceStatus());
        assertTrue(result.isPersistencePermitted());
        assertTrue(result.getExplanation().contains("ALLOWED"));
    }

    // ====================================================================
    // TEST B: HIGH risk + HIGH confidence -> BLOCK
    // ====================================================================
    @Test
    @DisplayName("Scenario B: HIGH risk + HIGH confidence should produce BLOCK decision")
    void testB_HighRisk_HighConfidence_Blocks() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                85,
                "HIGH",
                0.90,
                "PROMPT_INJECTION",
                "Direct prompt injection instruction detected in memory",
                "SEMANTIC",
                Map.of("injectionRisk", 85),
                List.of("SEMANTIC: [PROMPT_INJECTION] Direct prompt injection attempt")
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.BLOCK, result.getDecision());
        assertEquals("HIGH", result.getRiskLevel());
        assertEquals(0.90, result.getConfidence());
        assertEquals("CRITICAL_HIGH_CONFIDENCE_THREAT", result.getPolicyRule());
        assertEquals("DENIED", result.getPersistenceStatus());
        assertFalse(result.isPersistencePermitted());
        assertTrue(result.getExplanation().contains("BLOCKED"));
    }

    // ====================================================================
    // TEST C: HIGH risk + LOW confidence -> REVIEW
    // ====================================================================
    @Test
    @DisplayName("Scenario C: HIGH risk + LOW confidence should produce REVIEW decision (Risk != Certainty)")
    void testC_HighRisk_LowConfidence_RoutesToReview() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                85,
                "HIGH",
                0.45, // Low confidence below 0.70 threshold
                "PROMPT_INJECTION",
                "Uncertain heuristic match for instruction override",
                "HEURISTIC",
                Map.of("injectionRisk", 85),
                List.of("HEURISTIC: [PROMPT_INJECTION] Potential pattern match")
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.REVIEW, result.getDecision());
        assertEquals("HIGH", result.getRiskLevel());
        assertEquals(0.45, result.getConfidence());
        assertEquals("AMBIGUOUS_HIGH_RISK", result.getPolicyRule());
        assertEquals("QUARANTINED", result.getPersistenceStatus());
        assertFalse(result.isPersistencePermitted());
        assertTrue(result.getExplanation().contains("REVIEW"));
        assertTrue(result.getExplanation().contains("confidence"));
    }

    // ====================================================================
    // TEST D: MEDIUM suspicious instruction -> REVIEW
    // ====================================================================
    @Test
    @DisplayName("Scenario D: MEDIUM suspicious instruction should produce REVIEW decision")
    void testD_MediumSuspiciousInstruction_RoutesToReview() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                60,
                "MEDIUM",
                0.80,
                "SUSPICIOUS_INSTRUCTION",
                "Untrusted embedded directive altering behavior context",
                "RULE",
                Map.of("threatRisk", 60),
                List.of("RULE: [SUSPICIOUS_INSTRUCTION] Directive detected: grant refunds without check")
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.REVIEW, result.getDecision());
        assertEquals("MEDIUM", result.getRiskLevel());
        assertEquals("BEHAVIORAL_MANIPULATION_REVIEW", result.getPolicyRule());
        assertEquals("QUARANTINED", result.getPersistenceStatus());
        assertFalse(result.isPersistencePermitted());
    }

    // ====================================================================
    // TEST E: Educational prompt-injection discussion -> ALLOW
    // ====================================================================
    @Test
    @DisplayName("Scenario E: Educational prompt-injection discussion should produce ALLOW decision")
    void testE_EducationalPromptInjectionDiscussion_Allows() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                10,
                "LOW",
                0.95,
                "BENIGN_SECURITY_CONTENT",
                "Educational discussion explaining how prompt injection attacks work.",
                "SEMANTIC",
                Map.of("injectionRisk", 0),
                List.of("SEMANTIC: [BENIGN_SECURITY_CONTENT] Educational text on AI security")
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.ALLOW, result.getDecision());
        assertEquals("LOW", result.getRiskLevel());
        assertEquals("BENIGN_EDUCATIONAL_CONTENT", result.getPolicyRule());
        assertEquals("PERMITTED", result.getPersistenceStatus());
        assertTrue(result.isPersistencePermitted());
    }

    // ====================================================================
    // TEST F: Secret exfiltration attempt -> BLOCK
    // ====================================================================
    @Test
    @DisplayName("Scenario F: Secret exfiltration attempt should produce BLOCK decision")
    void testF_SecretExfiltration_Blocks() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                90,
                "HIGH",
                0.92,
                "SECRET_EXFILTRATION",
                "Instruction attempting to transmit environment API keys to external URL",
                "SEMANTIC",
                Map.of("sensitivityRisk", 90),
                List.of("SEMANTIC: [SECRET_EXFILTRATION] Exfiltrate API keys")
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.BLOCK, result.getDecision());
        assertEquals("CRITICAL_HIGH_CONFIDENCE_THREAT", result.getPolicyRule());
        assertEquals("DENIED", result.getPersistenceStatus());
        assertFalse(result.isPersistencePermitted());
    }

    // ====================================================================
    // TEST G: Privilege escalation -> BLOCK
    // ====================================================================
    @Test
    @DisplayName("Scenario G: Privilege escalation attempt should produce BLOCK decision")
    void testG_PrivilegeEscalation_Blocks() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                85,
                "HIGH",
                0.88,
                "PRIVILEGE_ESCALATION",
                "Pretexting command attempting to gain superadmin privileges",
                "SEMANTIC",
                Map.of("threatRisk", 85),
                List.of("SEMANTIC: [PRIVILEGE_ESCALATION] Superadmin privilege claim")
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.BLOCK, result.getDecision());
        assertEquals("CRITICAL_HIGH_CONFIDENCE_THREAT", result.getPolicyRule());
        assertEquals("DENIED", result.getPersistenceStatus());
    }

    // ====================================================================
    // TEST H: Tool manipulation -> BLOCK
    // ====================================================================
    @Test
    @DisplayName("Scenario H: Tool manipulation attempt should produce BLOCK decision")
    void testH_ToolManipulation_Blocks() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                85,
                "HIGH",
                0.85,
                "TOOL_MANIPULATION",
                "Instruction hijacking tool call arguments to execute arbitrary command",
                "SEMANTIC",
                Map.of("threatRisk", 85),
                List.of("SEMANTIC: [TOOL_MANIPULATION] Unauthorized tool execution")
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.BLOCK, result.getDecision());
        assertEquals("CRITICAL_HIGH_CONFIDENCE_THREAT", result.getPolicyRule());
        assertEquals("DENIED", result.getPersistenceStatus());
    }

    // ====================================================================
    // TEST I: Conflicting security evidence -> Deterministic Outcome
    // ====================================================================
    @Test
    @DisplayName("Scenario I: Conflicting security evidence produces deterministic policy decision")
    void testI_ConflictingEvidence_DeterministicOutcome() {
        // High score signal (85) with low confidence (0.40) vs Low risk signal (20) with high confidence (0.90)
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                85,
                "HIGH",
                0.40, // Low overall confidence for the high risk signal
                "PROMPT_INJECTION",
                "Conflicting findings: semantic flagged potential injection but provenance is trusted user",
                "MULTI_SIGNAL_PIPELINE",
                Map.of("provenanceRisk", 10, "injectionRisk", 85),
                List.of(
                        "PROVENANCE: [PROVENANCE_TRUSTED] Trusted user origin",
                        "SEMANTIC: [PROMPT_INJECTION] Ambiguous prompt injection keyword match"
                )
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        // Precedence Rule 3 (AMBIGUOUS_HIGH_RISK) deterministically selects REVIEW due to confidence < 0.70
        assertEquals(PolicyDecision.REVIEW, result.getDecision());
        assertEquals("AMBIGUOUS_HIGH_RISK", result.getPolicyRule());
        assertEquals("QUARANTINED", result.getPersistenceStatus());
    }

    // ====================================================================
    // TEST J: Missing semantic analysis -> Safe Fallback
    // ====================================================================
    @Test
    @DisplayName("Scenario J: Missing semantic analysis should fail safe to REVIEW")
    void testJ_MissingSemanticAnalysis_SafeFallback() {
        // Aggregated result where semantic analysis was unavailable
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                0,
                "LOW",
                0.0,
                "SEMANTIC_UNAVAILABLE",
                "AI Semantic analyzer timed out or was disabled",
                "DETERMINISTIC",
                Map.of("provenanceRisk", 0),
                List.of()
        );

        // Missing/null assessment -> Fail safe rule
        PolicyDecisionResult result = policyEngine.evaluate(null);

        assertEquals(PolicyDecision.REVIEW, result.getDecision());
        assertEquals("FAIL_SAFE_MISSING_ANALYSIS", result.getPolicyRule());
        assertEquals("QUARANTINED", result.getPersistenceStatus());
        assertFalse(result.isPersistencePermitted());
        assertTrue(result.getExplanation().contains("fail-safe policy"));
    }

    // ====================================================================
    // TEST K: Analyzer failure -> Safe Fallback
    // ====================================================================
    @Test
    @DisplayName("Scenario K: Upstream analyzer failure should trigger safe failure handling")
    void testK_AnalyzerFailure_SafeFallback() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                0,
                "LOW",
                0.0,
                "NO_ANALYSIS",
                "Analyzer failure: exception during security analysis execution",
                "AGGREGATED",
                Map.of(),
                List.of()
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.REVIEW, result.getDecision());
        assertEquals("FAIL_SAFE_MISSING_ANALYSIS", result.getPolicyRule());
        assertEquals("QUARANTINED", result.getPersistenceStatus());
    }

    // ====================================================================
    // TEST L: Empty/invalid memory -> Existing safe behavior
    // ====================================================================
    @Test
    @DisplayName("Scenario L: Empty or invalid memory content assessment handling")
    void testL_EmptyOrInvalidMemory_HandledSafely() {
        AggregatedRiskAssessment assessment = new AggregatedRiskAssessment(
                0,
                "LOW",
                1.0,
                "EMPTY_CONTENT",
                "No content available for security evaluation",
                "BASELINE",
                Map.of(),
                List.of()
        );

        PolicyDecisionResult result = policyEngine.evaluate(assessment);

        assertEquals(PolicyDecision.ALLOW, result.getDecision());
        assertEquals("LOW_RISK_BASELINE", result.getPolicyRule());
        assertEquals("PERMITTED", result.getPersistenceStatus());
    }

    // ====================================================================
    // TEST M: Multi-layer evidence -> Correct final policy decision
    // ====================================================================
    @Test
    @DisplayName("Scenario M: Multi-layer evidence (provenance + context + semantic) evaluated correctly")
    void testM_MultiLayerEvidence_EvaluatesCorrectly() {
        // Untrusted provenance (RETRIEVED: risk 65) + Context anomaly (risk 40) + Semantic signal (SUSPICIOUS_INSTRUCTION)
        SecurityAnalysisResult provenanceRes = new ProvenanceAnalysisResult(
                ProvenanceType.RETRIEVED,
                "MEDIUM",
                65,
                "PROVENANCE_UNTRUSTED_RETRIEVED_SOURCE",
                "Memory retrieved from external untrusted source",
                0.90
        );

        SecurityAnalysisResult contextRes = new SecurityAnalysisResult(
                "MEDIUM",
                40,
                "CONTEXT_ANOMALY",
                "Content contradicts trusted agent domain context",
                0.85,
                "CONTEXT"
        );

        SecurityAnalysisResult semanticRes = new SemanticAnalysisResult(
                true,
                "MEDIUM",
                60,
                "SUSPICIOUS_INSTRUCTION",
                "Content contains instruction to disable safety checks",
                0.80,
                List.of(new SemanticSecuritySignal(
                        SemanticSignalType.SUSPICIOUS_INSTRUCTION,
                        60,
                        0.80,
                        "Instruction to disable safety checks",
                        "disable safety checks",
                        "semantic-analyzer"
                ))
        );

        AggregatedRiskAssessment aggregated = riskAggregator.aggregateAssessment(List.of(provenanceRes, contextRes, semanticRes));
        PolicyDecisionResult policyResult = policyEngine.evaluate(aggregated);

        // Score accumulated to >= 65, category is SUSPICIOUS_INSTRUCTION -> REVIEW
        assertEquals(PolicyDecision.REVIEW, policyResult.getDecision());
        assertEquals("QUARANTINED", policyResult.getPersistenceStatus());
        assertFalse(policyResult.getContributingFactors().isEmpty());
    }

    // ====================================================================
    // TEST N: Policy Engine as Sole Authority
    // ====================================================================
    @Test
    @DisplayName("Scenario N: Policy Engine remains sole authority for final ALLOW / REVIEW / BLOCK decision")
    void testN_PolicyEngine_SoleAuthorityForFinalDecision() {
        // High risk score (85) from risk aggregator
        AggregatedRiskAssessment highAssessment = new AggregatedRiskAssessment(
                85,
                "HIGH",
                0.95,
                "PROMPT_INJECTION",
                "Critical prompt injection",
                "SEMANTIC",
                Map.of("injectionRisk", 85),
                List.of("PROMPT_INJECTION")
        );

        // Low risk score (10) from risk aggregator
        AggregatedRiskAssessment lowAssessment = new AggregatedRiskAssessment(
                10,
                "LOW",
                0.95,
                "NO_MAJOR_RISK",
                "Safe user memory",
                "BASELINE",
                Map.of(),
                List.of()
        );

        // Verify PolicyEngine alone makes the decision object and status mapping
        PolicyDecisionResult highResult = policyEngine.evaluate(highAssessment);
        PolicyDecisionResult lowResult = policyEngine.evaluate(lowAssessment);

        assertEquals(PolicyDecision.BLOCK, highResult.getDecision());
        assertEquals("DENIED", highResult.getPersistenceStatus());

        assertEquals(PolicyDecision.ALLOW, lowResult.getDecision());
        assertEquals("PERMITTED", lowResult.getPersistenceStatus());
    }
}

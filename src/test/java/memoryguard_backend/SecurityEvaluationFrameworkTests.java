package memoryguard_backend;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.evaluation.*;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.repository.SecurityLogRepository;
import memoryguard_backend.security.*;
import memoryguard_backend.security.context.ContextAnalyzer;
import memoryguard_backend.security.signals.SecuritySignalExtractor;
import memoryguard_backend.security.content.MemoryContentAnalyzer;
import memoryguard_backend.security.risk.MemoryRiskAggregator;
import memoryguard_backend.service.MemoryService;
import memoryguard_backend.service.SecurityLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecurityEvaluationFrameworkTests {

    private SecurityEvaluationService evaluationService;

    @BeforeEach
    void setUp() {
        MemoryRepository memoryRepository = mock(MemoryRepository.class);
        SecurityLogRepository securityLogRepository = mock(SecurityLogRepository.class);
        SecurityLogService securityLogService = new SecurityLogService(securityLogRepository);

        PolicyProperties policyProperties = new PolicyProperties();
        policyProperties.setBlockThreshold(80);
        policyProperties.setReviewThreshold(50);
        policyProperties.setCriticalThreatAutoBlock(true);
        PolicyEngine policyEngine = new PolicyEngine(policyProperties);

        RiskAggregator riskAggregator = new RiskAggregator();
        ProvenanceAnalyzer provenanceAnalyzer = new ProvenanceAnalyzer();
        ContextAnalyzer contextAnalyzer = new ContextAnalyzer();
        BaselineSemanticAnalyzer baselineSemanticAnalyzer = new BaselineSemanticAnalyzer();

        when(memoryRepository.save(any(Memory.class))).thenAnswer(invocation -> {
            Memory m = invocation.getArgument(0);
            if (m.getId() == null) {
                m.setId((long) (Math.random() * 10000 + 1));
            }
            return m;
        });

        when(securityLogRepository.save(any(SecurityLog.class))).thenAnswer(invocation -> invocation.getArgument(0));

        MemoryService memoryService = new MemoryService(
                memoryRepository,
                List.of(baselineSemanticAnalyzer),
                provenanceAnalyzer,
                contextAnalyzer,
                new SecuritySignalExtractor(),
                new MemoryContentAnalyzer(),
                new MemoryRiskAggregator(),
                securityLogService,
                policyEngine,
                riskAggregator,
                null,
                null
        );

        evaluationService = new SecurityEvaluationService(memoryService);
    }

    @Test
    void testDatasetLoadingAndSchemaValidation() {
        List<EvaluationScenario> scenarios = evaluationService.loadScenarios();
        assertNotNull(scenarios, "Scenarios list must not be null");
        assertTrue(scenarios.size() >= 30, "Dataset must contain at least 30 scenarios");

        for (EvaluationScenario scenario : scenarios) {
            assertNotNull(scenario.getId(), "Scenario ID required");
            assertNotNull(scenario.getMemoryContent(), "Memory content required");
            assertNotNull(scenario.getProvenance(), "Provenance required");
            assertNotNull(scenario.getExpectedCategory(), "Expected category required");
            assertNotNull(scenario.getExpectedDecision(), "Expected decision required");
        }
    }

    @Test
    void testEndToEndPipelineEvaluationAndMetrics() {
        EvaluationReport report = evaluationService.runEvaluation();
        assertNotNull(report, "Report should not be null");
        assertTrue(report.getDatasetSize() >= 30, "Dataset size should be >= 30");

        SecurityMetrics m = report.getOverallMetrics();
        assertNotNull(m, "Metrics should not be null");

        System.out.println("====== SECURITY EVALUATION SUITE METRICS ======");
        System.out.printf("Total Scenarios Evaluated: %d%n", m.getTotalScenarios());
        System.out.printf("Accuracy: %.4f, Precision: %.4f, Recall: %.4f, F1: %.4f%n",
                m.getOverallAccuracy(), m.getPrecision(), m.getRecall(), m.getF1Score());
        System.out.printf("FPR: %.4f, FNR: %.4f%n", m.getFalsePositiveRate(), m.getFalseNegativeRate());
        System.out.printf("Decision Distribution -> ALLOW: %d, REVIEW: %d, BLOCK: %d%n",
                m.getAllowCount(), m.getReviewCount(), m.getBlockCount());

        // Core Security Invariant: Zero False Negatives
        assertEquals(0, m.getFalseNegatives(), "False Negative count MUST be zero — no malicious memory payloads allowed!");
        assertTrue(m.getRecall() >= 0.95, "Recall must meet or exceed 95%");
        assertTrue(m.getOverallAccuracy() >= 0.50, "Overall Accuracy should be valid");
        assertTrue(m.getPrecision() >= 0.50, "Precision should be valid");
        assertTrue(m.getF1Score() >= 0.50, "F1 Score should be valid");

        assertNotNull(m.getCategoryMetrics());
        assertFalse(m.getCategoryMetrics().isEmpty());
    }

    @Test
    void testFalsePositiveAndFalseNegativeTracking() {
        EvaluationReport report = evaluationService.runEvaluation();
        assertNotNull(report.getFalsePositives());
        assertNotNull(report.getFalseNegatives());
        assertEquals(0, report.getFalseNegatives().size(), "Zero false negatives expected");
    }

    @Test
    void testProvenanceContrastAnalysis() {
        EvaluationReport report = evaluationService.runEvaluation();
        assertNotNull(report.getProvenanceComparisonFindings());
        assertFalse(report.getProvenanceComparisonFindings().isEmpty(), "Provenance comparison findings should be populated");
    }

    @Test
    void testAdversarialTestFindings() {
        EvaluationReport report = evaluationService.runEvaluation();
        assertNotNull(report.getAdversarialTestFindings());
        assertFalse(report.getAdversarialTestFindings().isEmpty(), "Adversarial test findings should be populated");
    }

    @Test
    void testJsonReportGeneration() {
        evaluationService.runEvaluation();
        File reportFile = new File("evaluation/reports/latest_evaluation.json");
        assertTrue(reportFile.exists(), "latest_evaluation.json report file must be generated");
        assertTrue(reportFile.length() > 0, "Report file must not be empty");

        File advReportFile = new File("evaluation/reports/adversarial_evaluation_report.json");
        assertTrue(advReportFile.exists(), "adversarial_evaluation_report.json must be generated");
        assertTrue(advReportFile.length() > 0, "Adversarial report file must not be empty");
    }

    @Test
    void testTenAttackCategoriesCovered() {
        EvaluationReport report = evaluationService.runEvaluation();
        assertNotNull(report.getCategoryResults(), "Category results must be present");
        assertTrue(report.getCategoryResults().keySet().size() >= 10, "Report must cover at least 10 attack categories");

        String[] requiredCategories = {
                "BENIGN", "DIRECT_PROMPT_INJECTION", "INDIRECT_PROMPT_INJECTION",
                "MEMORY_POISONING", "INSTRUCTION_OVERRIDE", "MALICIOUS_SLEEPER_MEMORY",
                "SECRET_LEAKAGE", "CONTRADICTORY_MEMORY", "SOCIAL_ENGINEERING", "OBFUSCATED_EVASIVE"
        };

        for (String category : requiredCategories) {
            assertTrue(report.getCategoryResults().containsKey(category), "Missing required attack category: " + category);
        }
    }

    @Test
    void testDetectorContributionsAttribution() {
        EvaluationReport report = evaluationService.runEvaluation();
        assertNotNull(report.getDetectorContributions(), "Detector contributions must be present");
        EvaluationReport.DetectorContributions contribs = report.getDetectorContributions();

        assertTrue(contribs.getRuleOnly() >= 0, "Rule-only count must be non-negative");
        assertTrue(contribs.getSemanticOnly() >= 0, "Semantic-only count must be non-negative");
        assertTrue(contribs.getBoth() >= 0, "Both count must be non-negative");
        assertTrue(contribs.getNeither() >= 0, "Neither count must be non-negative");

        int sum = contribs.getRuleOnly() + contribs.getSemanticOnly() + contribs.getBoth() + contribs.getNeither();
        assertEquals(report.getTotalCases(), sum, "Sum of detector attributions must equal total dataset size");
    }
}

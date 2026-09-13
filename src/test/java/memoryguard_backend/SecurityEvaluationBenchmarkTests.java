package memoryguard_backend;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.evaluation.*;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.repository.SecurityLogRepository;
import memoryguard_backend.security.*;
import memoryguard_backend.security.content.MemoryContentAnalyzer;
import memoryguard_backend.security.context.ContextAnalyzer;
import memoryguard_backend.security.risk.MemoryRiskAggregator;
import memoryguard_backend.security.signals.SecuritySignalExtractor;
import memoryguard_backend.service.MemoryService;
import memoryguard_backend.service.SecurityLogService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class SecurityEvaluationBenchmarkTests {

    private SecurityEvaluationService evaluationService;
    private DatasetValidator datasetValidator;
    private MemoryRepository memoryRepository;

    @BeforeEach
    void setUp() {
        memoryRepository = mock(MemoryRepository.class);
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
        datasetValidator = new DatasetValidator();
    }

    // ====================================================================
    // 1. DATASET LOADING & VALIDATION TESTS
    // ====================================================================

    @Test
    @DisplayName("Benchmark dataset loads successfully and passes validation")
    void testDatasetLoading_BenchmarkDatasetLoadedSuccessfully() {
        List<EvaluationScenario> scenarios = evaluationService.loadScenarios();

        assertNotNull(scenarios, "Benchmark scenarios must not be null");
        assertFalse(scenarios.isEmpty(), "Benchmark scenarios must not be empty");
        assertTrue(scenarios.size() >= 15, "Benchmark dataset should contain at least 15 representative scenarios");

        assertDoesNotThrow(() -> datasetValidator.validate(scenarios));
    }

    @Test
    @DisplayName("DatasetValidator rejects null or empty dataset")
    void testDatasetValidator_NullOrEmptyDatasetThrowsException() {
        assertThrows(DatasetValidationException.class, () -> datasetValidator.validate(null));
        assertThrows(DatasetValidationException.class, () -> datasetValidator.validate(List.of()));
    }

    @Test
    @DisplayName("DatasetValidator detects duplicate case IDs and throws exception")
    void testDatasetValidator_DuplicateCaseIdThrowsException() {
        EvaluationScenario s1 = new EvaluationScenario();
        s1.setId("CASE-001");
        s1.setMemoryContent("Content 1");
        s1.setProvenance("USER_INPUT");
        s1.setExpectedCategory("NORMAL");
        s1.setExpectedDecision("ALLOW");

        EvaluationScenario s2 = new EvaluationScenario();
        s2.setId("CASE-001"); // Duplicate!
        s2.setMemoryContent("Content 2");
        s2.setProvenance("USER_INPUT");
        s2.setExpectedCategory("NORMAL");
        s2.setExpectedDecision("ALLOW");

        List<EvaluationScenario> scenarios = List.of(s1, s2);

        DatasetValidationException ex = assertThrows(DatasetValidationException.class, () -> datasetValidator.validate(scenarios));
        assertTrue(ex.getMessage().contains("Duplicate case ID detected"));
    }

    @Test
    @DisplayName("DatasetValidator detects missing required fields")
    void testDatasetValidator_MissingRequiredFieldThrowsException() {
        EvaluationScenario s = new EvaluationScenario();
        s.setId("CASE-002");
        // Missing memoryContent!
        s.setProvenance("USER_INPUT");
        s.setExpectedCategory("NORMAL");
        s.setExpectedDecision("ALLOW");

        assertThrows(DatasetValidationException.class, () -> datasetValidator.validate(List.of(s)));
    }

    @Test
    @DisplayName("DatasetValidator rejects invalid expected decisions")
    void testDatasetValidator_InvalidExpectedDecisionThrowsException() {
        EvaluationScenario s = new EvaluationScenario();
        s.setId("CASE-003");
        s.setMemoryContent("Valid memory content");
        s.setProvenance("USER_INPUT");
        s.setExpectedCategory("NORMAL");
        s.setExpectedDecision("INVALID_DECISION"); // Invalid!

        assertThrows(DatasetValidationException.class, () -> datasetValidator.validate(List.of(s)));
    }

    @Test
    @DisplayName("DatasetValidator rejects invalid expected risk levels")
    void testDatasetValidator_InvalidExpectedRiskLevelThrowsException() {
        EvaluationScenario s = new EvaluationScenario();
        s.setId("CASE-004");
        s.setMemoryContent("Valid memory content");
        s.setProvenance("USER_INPUT");
        s.setExpectedCategory("NORMAL");
        s.setExpectedDecision("ALLOW");
        s.setExpectedRiskLevel("EXTREME_DANGER"); // Invalid!

        assertThrows(DatasetValidationException.class, () -> datasetValidator.validate(List.of(s)));
    }

    @Test
    @DisplayName("DatasetValidator verifies representation across all 9 required categories")
    void testDatasetValidator_AllNineRequiredCategoriesRepresented() {
        List<EvaluationScenario> scenarios = evaluationService.loadScenarios();

        assertDoesNotThrow(() -> datasetValidator.validate(scenarios));
    }

    // ====================================================================
    // 2. SEMANTIC EDGE CASES TESTS
    // ====================================================================

    @Test
    @DisplayName("Semantic edge case: Password statement vs password credential exposure")
    void testSemanticEdgeCase_PasswordStatementVsPasswordExposure() {
        List<EvaluationScenario> scenarios = evaluationService.loadScenarios();

        EvaluationScenario passwordDirective = scenarios.stream()
                .filter(s -> s.getMemoryContent().contains("Never store a user's password"))
                .findFirst()
                .orElse(null);

        assertNotNull(passwordDirective, "Password policy directive scenario should be present");
        assertEquals("ALLOW", passwordDirective.getExpectedDecision());

        EvaluationScenario passwordExposure = scenarios.stream()
                .filter(s -> s.getMemoryContent().contains("My password is"))
                .findFirst()
                .orElse(null);

        assertNotNull(passwordExposure, "Password exposure scenario should be present");
        assertEquals("BLOCK", passwordExposure.getExpectedDecision());
    }

    // ====================================================================
    // 3. DUAL EVALUATION MODES TESTS
    // ====================================================================

    @Test
    @DisplayName("RULES_ONLY evaluation mode executes deterministically")
    void testEvaluationMode_RulesOnlyExecution() {
        EvaluationReport report = evaluationService.runEvaluation(EvaluationMode.RULES_ONLY);

        assertNotNull(report);
        assertTrue(report.getDatasetSize() >= 15);
        assertNotNull(report.getOverallMetrics());
        assertTrue(report.getOverallMetrics().getF1Score() >= 0.30);
    }

    @Test
    @DisplayName("RULES_PLUS_AI evaluation mode executes full pipeline")
    void testEvaluationMode_RulesPlusAiExecution() {
        EvaluationReport report = evaluationService.runEvaluation(EvaluationMode.RULES_PLUS_AI);

        assertNotNull(report);
        assertTrue(report.getDatasetSize() >= 15);
        assertNotNull(report.getOverallMetrics());
        assertTrue(report.getOverallMetrics().getF1Score() >= 0.50);
    }

    @Test
    @DisplayName("Comparative evaluation mode compares RULES_ONLY vs RULES_PLUS_AI side-by-side")
    void testComparativeEvaluation_GeneratesComparativeReport() {
        EvaluationReport report = evaluationService.runEvaluation(EvaluationMode.COMPARATIVE);

        assertNotNull(report);
        assertNotNull(report.getCriticalFindings());
        assertFalse(report.getCriticalFindings().isEmpty());
        assertTrue(report.getCriticalFindings().stream().anyMatch(f -> f.contains("RULES_ONLY")));
        assertTrue(report.getCriticalFindings().stream().anyMatch(f -> f.contains("RULES_PLUS_AI")));
    }

    // ====================================================================
    // 4. CONFUSION MATRIX & METRICS CALCULATION TESTS
    // ====================================================================

    @Test
    @DisplayName("ConfusionMatrix records decisions and calculates accuracy, precision, recall, F1 score")
    void testConfusionMatrix_RecordAndCalculateMetricsAccurately() {
        ConfusionMatrix cm = new ConfusionMatrix();

        // 2 TP (expected BLOCK, predicted BLOCK)
        cm.record("BLOCK", "BLOCK");
        cm.record("BLOCK", "BLOCK");

        // 2 TN (expected ALLOW, predicted ALLOW)
        cm.record("ALLOW", "ALLOW");
        cm.record("ALLOW", "ALLOW");

        // 1 FP (expected ALLOW, predicted REVIEW)
        cm.record("ALLOW", "REVIEW");

        // 1 FN (expected BLOCK, predicted ALLOW)
        cm.record("BLOCK", "ALLOW");

        assertEquals(2, cm.getTruePositives());
        assertEquals(2, cm.getTrueNegatives());
        assertEquals(1, cm.getFalsePositives());
        assertEquals(1, cm.getFalseNegatives());

        assertEquals(4.0 / 6.0, cm.getAccuracy(), 0.001);
        assertEquals(2.0 / 3.0, cm.getPrecision(), 0.001);
        assertEquals(2.0 / 3.0, cm.getRecall(), 0.001);
        assertEquals(2.0 / 3.0, cm.getF1Score(), 0.001);
    }

    @Test
    @DisplayName("ConfusionMatrix handles zero predicted positives safely without division by zero")
    void testConfusionMatrix_ZeroPositiveEdgeCasesHandledSafely() {
        ConfusionMatrix cm = new ConfusionMatrix();

        // 0 observations
        assertEquals(0.0, cm.getAccuracy());
        assertEquals(1.0, cm.getPrecision());
        assertEquals(1.0, cm.getRecall());
        assertEquals(0.0, cm.getF1Score());
        assertEquals(0.0, cm.getFalsePositiveRate());
        assertEquals(0.0, cm.getFalseNegativeRate());
    }

    @Test
    @DisplayName("Category-level metrics computed accurately across threat categories")
    void testCategoryLevelMetrics_CalculatesPerCategoryStats() {
        EvaluationReport report = evaluationService.runEvaluation(EvaluationMode.RULES_PLUS_AI);

        assertNotNull(report.getOverallMetrics().getCategoryMetrics());
        assertFalse(report.getOverallMetrics().getCategoryMetrics().isEmpty());

        SecurityMetrics.CategoryMetric normMetric = report.getOverallMetrics().getCategoryMetrics().get("NORMAL");
        if (normMetric == null) {
            normMetric = report.getOverallMetrics().getCategoryMetrics().get("BENIGN");
        }
        assertNotNull(normMetric, "Category metrics for NORMAL / BENIGN should be present");
        assertTrue(normMetric.getTotal() >= 1);
    }

    // ====================================================================
    // 5. PRODUCTION STORAGE ISOLATION & REGRESSION TESTS
    // ====================================================================

    @Test
    @DisplayName("Benchmark execution does not insert records into production memory database")
    void testProductionIsolation_BenchmarkExecutionDoesNotWriteToDatabase() {
        evaluationService.runEvaluation(EvaluationMode.RULES_PLUS_AI);

        // Verify production memory repository was never invoked to save benchmark records
        verify(memoryRepository, never()).save(any(Memory.class));
    }

    @Test
    @DisplayName("REST Controller endpoints accept evaluation mode parameters and return reports")
    void testEvaluationController_EndpointsReturnReports() {
        EvaluationController controller = new EvaluationController(evaluationService);

        ResponseEntity<EvaluationReport> runResp = controller.runEvaluation("RULES_ONLY");
        assertEquals(HttpStatus.OK, runResp.getStatusCode());
        assertNotNull(runResp.getBody());

        ResponseEntity<EvaluationReport> benchResp = controller.runBenchmark("COMPARATIVE");
        assertEquals(HttpStatus.OK, benchResp.getStatusCode());
        assertNotNull(benchResp.getBody());
    }

    @Test
    @DisplayName("Deterministic dataset loading guarantees reproducible test results")
    void testDeterministicDatasetLoading_ReproducibleResults() {
        EvaluationReport report1 = evaluationService.runEvaluation(EvaluationMode.RULES_PLUS_AI);
        EvaluationReport report2 = evaluationService.runEvaluation(EvaluationMode.RULES_PLUS_AI);

        assertEquals(report1.getDatasetSize(), report2.getDatasetSize());
        assertEquals(report1.getOverallMetrics().getOverallAccuracy(), report2.getOverallMetrics().getOverallAccuracy(), 0.0001);
        assertEquals(report1.getOverallMetrics().getF1Score(), report2.getOverallMetrics().getF1Score(), 0.0001);
    }
}

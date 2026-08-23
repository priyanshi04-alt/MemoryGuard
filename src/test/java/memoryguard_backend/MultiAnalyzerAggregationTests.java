package memoryguard_backend;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.security.*;
import memoryguard_backend.service.MemoryService;
import memoryguard_backend.service.SecurityLogService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MultiAnalyzerAggregationTests {

    private RiskAggregator riskAggregator;
    private MemoryRepository memoryRepository;
    private SecurityLogService securityLogService;
    private PolicyEngine policyEngine;
    private ExecutorService testExecutor;
    private SecurityAnalysisProperties testProperties;

    @BeforeEach
    void setUp() {
        riskAggregator = new RiskAggregator();
        memoryRepository = mock(MemoryRepository.class);
        securityLogService = mock(SecurityLogService.class);
        policyEngine = new PolicyEngine();

        testProperties = new SecurityAnalysisProperties();
        testProperties.setParallelism(2);
        testProperties.setTimeoutMs(1000);
        testExecutor = Executors.newFixedThreadPool(2);
    }

    @AfterEach
    void tearDown() {
        if (testExecutor != null) {
            testExecutor.shutdownNow();
        }
    }

    @Test
    void testRiskAggregatorRuleLowAiLow() {
        SecurityAnalysisResult rule = new SecurityAnalysisResult("LOW", 10, "NONE", "Rule safe", 1.0, "RULE");
        SecurityAnalysisResult ai = new SecurityAnalysisResult("LOW", 15, "NONE", "AI safe", 0.95, "SEMANTIC");

        SecurityAnalysisResult aggregated = riskAggregator.aggregate(List.of(rule, ai));
        assertEquals(15, aggregated.getRiskScore());
        assertEquals("LOW", aggregated.getRiskLevel());
    }

    @Test
    void testRiskAggregatorRuleLowAiHigh() {
        SecurityAnalysisResult rule = new SecurityAnalysisResult("LOW", 10, "NONE", "Rule safe", 1.0, "RULE");
        SecurityAnalysisResult ai = new SecurityAnalysisResult("HIGH", 85, "PROMPT_INJECTION", "AI alert", 0.95, "SEMANTIC");

        SecurityAnalysisResult aggregated = riskAggregator.aggregate(List.of(rule, ai));
        assertEquals(85, aggregated.getRiskScore());
        assertEquals("HIGH", aggregated.getRiskLevel());
        assertEquals("PROMPT_INJECTION", aggregated.getCategory());
    }

    @Test
    void testRiskAggregatorRuleHighAiLow() {
        SecurityAnalysisResult rule = new SecurityAnalysisResult("HIGH", 90, "CREDENTIAL_LEAK", "Rule alert", 1.0, "RULE");
        SecurityAnalysisResult ai = new SecurityAnalysisResult("LOW", 10, "NONE", "AI safe", 0.95, "SEMANTIC");

        SecurityAnalysisResult aggregated = riskAggregator.aggregate(List.of(rule, ai));
        assertEquals(90, aggregated.getRiskScore());
        assertEquals("HIGH", aggregated.getRiskLevel());
        assertEquals("CREDENTIAL_LEAK", aggregated.getCategory());
    }

    @Test
    void testRiskAggregatorRuleHighAiUnavailable() {
        SecurityAnalysisResult rule = new SecurityAnalysisResult("HIGH", 90, "CREDENTIAL_LEAK", "Rule alert", 1.0, "RULE");
        SecurityAnalysisResult ai = new SecurityAnalysisResult("LOW", 0, "SEMANTIC_UNAVAILABLE", "AI offline", 0.0, "SEMANTIC");

        SecurityAnalysisResult aggregated = riskAggregator.aggregate(List.of(rule, ai));
        assertEquals(90, aggregated.getRiskScore());
        assertEquals("HIGH", aggregated.getRiskLevel());
        assertEquals("CREDENTIAL_LEAK", aggregated.getCategory());
    }

    @Test
    void testRiskAggregatorRuleMediumAiHigh() {
        SecurityAnalysisResult rule = new SecurityAnalysisResult("MEDIUM", 50, "SQL_INJECTION", "Rule warning", 1.0, "RULE");
        SecurityAnalysisResult ai = new SecurityAnalysisResult("HIGH", 80, "PROMPT_INJECTION", "AI alert", 0.95, "SEMANTIC");

        SecurityAnalysisResult aggregated = riskAggregator.aggregate(List.of(rule, ai));
        assertEquals(80, aggregated.getRiskScore());
        assertEquals("HIGH", aggregated.getRiskLevel());
    }

    @Test
    void testRiskAggregatorDeterministicBlockCannotBeDowngraded() {
        SecurityAnalysisResult rule = new SecurityAnalysisResult("HIGH", 95, "CREDENTIAL_LEAK", "Rule block", 1.0, "RULE");
        SecurityAnalysisResult ai = new SecurityAnalysisResult("LOW", 5, "NONE", "AI safe", 0.95, "SEMANTIC");

        SecurityAnalysisResult aggregated = riskAggregator.aggregate(List.of(rule, ai));
        assertEquals(95, aggregated.getRiskScore());
        assertEquals("HIGH", aggregated.getRiskLevel());
    }

    @Test
    void testRiskAggregatorSemanticUnavailableIgnoredByAggregation() {
        SecurityAnalysisResult rule = new SecurityAnalysisResult("MEDIUM", 60, "NONE", "Rule content", 1.0, "RULE");
        SecurityAnalysisResult ai = new SecurityAnalysisResult("LOW", 0, "SEMANTIC_UNAVAILABLE", "AI offline", 0.0, "SEMANTIC");

        SecurityAnalysisResult aggregated = riskAggregator.aggregate(List.of(rule, ai));
        assertEquals(60, aggregated.getRiskScore());
        assertEquals("MEDIUM", aggregated.getRiskLevel());
    }

    @Test
    void testMemoryServiceOnlyDeterministicAnalyzerAvailable() {
        SecurityAnalyzer mockRuleAnalyzer = mock(SecurityAnalyzer.class);
        SecurityAnalysisResult ruleResult = new SecurityAnalysisResult("LOW", 10, "NONE", "Rule result", 1.0, "RULE");
        when(mockRuleAnalyzer.analyze(anyString())).thenReturn(ruleResult);

        MemoryService service = new MemoryService(
                memoryRepository,
                List.of(mockRuleAnalyzer),
                securityLogService,
                policyEngine,
                riskAggregator,
                testExecutor,
                testProperties
        );

        Memory memory = new Memory();
        memory.setContent("Hello world");

        service.createMemory(memory);
        assertEquals(10, memory.getRiskScore());
        assertEquals("LOW", memory.getRiskLevel());
        verify(mockRuleAnalyzer, times(1)).analyze("Hello world");
    }

    @Test
    void testMemoryServiceBothAnalyzersAvailable() {
        SecurityAnalyzer mockRuleAnalyzer = mock(SecurityAnalyzer.class);
        SecurityAnalyzer mockSemanticAnalyzer = mock(SecurityAnalyzer.class);

        SecurityAnalysisResult ruleResult = new SecurityAnalysisResult("LOW", 10, "NONE", "Rule result", 1.0, "RULE");
        SecurityAnalysisResult aiResult = new SecurityAnalysisResult("HIGH", 85, "PROMPT_INJECTION", "AI result", 0.95, "SEMANTIC");

        when(mockRuleAnalyzer.analyze(anyString())).thenReturn(ruleResult);
        when(mockSemanticAnalyzer.analyze(anyString())).thenReturn(aiResult);

        MemoryService service = new MemoryService(
                memoryRepository,
                List.of(mockRuleAnalyzer, mockSemanticAnalyzer),
                securityLogService,
                policyEngine,
                riskAggregator,
                testExecutor,
                testProperties
        );

        Memory memory = new Memory();
        memory.setContent("Test query");

        service.createMemory(memory);
        assertEquals(85, memory.getRiskScore());
        assertEquals("HIGH", memory.getRiskLevel());
        verify(mockRuleAnalyzer, times(1)).analyze("Test query");
        verify(mockSemanticAnalyzer, times(1)).analyze("Test query");
    }

    @Test
    void testMemoryServiceBothAnalyzersAiDisabled() {
        SecurityAnalyzer mockRuleAnalyzer = mock(SecurityAnalyzer.class);
        SecurityAnalyzer mockSemanticAnalyzer = mock(SecurityAnalyzer.class);

        SecurityAnalysisResult ruleResult = new SecurityAnalysisResult("MEDIUM", 50, "NONE", "Rule result", 1.0, "RULE");
        SecurityAnalysisResult aiResult = new SecurityAnalysisResult("LOW", 0, "SEMANTIC_UNAVAILABLE", "AI disabled", 0.0, "SEMANTIC");

        when(mockRuleAnalyzer.analyze(anyString())).thenReturn(ruleResult);
        when(mockSemanticAnalyzer.analyze(anyString())).thenReturn(aiResult);

        MemoryService service = new MemoryService(
                memoryRepository,
                List.of(mockRuleAnalyzer, mockSemanticAnalyzer),
                securityLogService,
                policyEngine,
                riskAggregator,
                testExecutor,
                testProperties
        );

        Memory memory = new Memory();
        memory.setContent("Test query");

        service.createMemory(memory);
        assertEquals(50, memory.getRiskScore());
        assertEquals("MEDIUM", memory.getRiskLevel());
    }

    @Test
    void testMemoryServiceBothAnalyzersAiUnavailable() {
        SecurityAnalyzer mockRuleAnalyzer = mock(SecurityAnalyzer.class);
        SecurityAnalyzer mockSemanticAnalyzer = mock(SecurityAnalyzer.class);

        SecurityAnalysisResult ruleResult = new SecurityAnalysisResult("MEDIUM", 60, "NONE", "Rule result", 1.0, "RULE");
        SecurityAnalysisResult aiResult = new SecurityAnalysisResult("LOW", 0, "SEMANTIC_UNAVAILABLE", "AI failed", 0.0, "SEMANTIC");

        when(mockRuleAnalyzer.analyze(anyString())).thenReturn(ruleResult);
        when(mockSemanticAnalyzer.analyze(anyString())).thenReturn(aiResult);

        MemoryService service = new MemoryService(
                memoryRepository,
                List.of(mockRuleAnalyzer, mockSemanticAnalyzer),
                securityLogService,
                policyEngine,
                riskAggregator,
                testExecutor,
                testProperties
        );

        Memory memory = new Memory();
        memory.setContent("Test query");

        service.createMemory(memory);
        assertEquals(60, memory.getRiskScore());
        assertEquals("MEDIUM", memory.getRiskLevel());
    }
}

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
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class ConcurrencyTimeoutTests {

    private ExecutorService testExecutor;
    private SecurityAnalysisProperties testProperties;
    private MemoryRepository memoryRepository;
    private SecurityLogService securityLogService;
    private PolicyEngine policyEngine;
    private RiskAggregator riskAggregator;

    @BeforeEach
    void setUp() {
        testProperties = new SecurityAnalysisProperties();
        testProperties.setParallelism(2);
        testProperties.setTimeoutMs(150); // Small test timeout

        testExecutor = new ThreadPoolExecutor(
                2, 2, 0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(10)
        );

        memoryRepository = mock(MemoryRepository.class);
        securityLogService = mock(SecurityLogService.class);
        policyEngine = new PolicyEngine();
        riskAggregator = new RiskAggregator();
    }

    @AfterEach
    void tearDown() {
        if (testExecutor != null) {
            testExecutor.shutdownNow();
        }
    }

    @Test
    void testGenuinelyParallelExecution() throws InterruptedException {
        CountDownLatch latchAStart = new CountDownLatch(1);
        CountDownLatch latchBStart = new CountDownLatch(1);
        CountDownLatch latchARelease = new CountDownLatch(1);
        CountDownLatch latchBRelease = new CountDownLatch(1);

        SecurityAnalyzer analyzerA = content -> {
            latchAStart.countDown();
            try {
                latchARelease.await(2, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return new SecurityAnalysisResult("LOW", 10, "NONE", "Analyzer A", 1.0, "RULE");
        };

        // Custom analyzer class representing AISemanticSecurityAnalyzer
        SecurityAnalyzer mockSemanticAnalyzer = new AISemanticSecurityAnalyzer(null, null) {
            @Override
            public SecurityAnalysisResult analyze(String content) {
                latchBStart.countDown();
                try {
                    latchBRelease.await(2, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return new SecurityAnalysisResult("LOW", 20, "NONE", "Analyzer B", 1.0, "SEMANTIC");
            }
        };

        MemoryService service = new MemoryService(
                memoryRepository,
                List.of(analyzerA, mockSemanticAnalyzer),
                securityLogService,
                policyEngine,
                riskAggregator,
                testExecutor,
                testProperties
        );

        Memory memory = new Memory();
        memory.setContent("Hello");

        // Submit analysis task in a separate thread so it doesn't block the test
        Future<?> testRun = Executors.newSingleThreadExecutor().submit(() -> service.createMemory(memory));

        // Verify both threads have started execution concurrently
        boolean bothStarted = latchAStart.await(2, TimeUnit.SECONDS) && latchBStart.await(2, TimeUnit.SECONDS);
        assertTrue(bothStarted, "Both analyzers should have started execution concurrently");

        // Release both to finish
        latchARelease.countDown();
        latchBRelease.countDown();

        try {
            testRun.get(2, TimeUnit.SECONDS);
        } catch (Exception e) {
            fail("Parallel execution run failed: " + e.getMessage());
        }

        assertEquals(20, memory.getRiskScore());
    }

    @Test
    void testAIAnalyzerTimeoutDoesNotDiscardDeterministicResult() {
        // Deterministic completes quickly
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("HIGH", 90, "RULE_BLOCK", "Rule matched", 1.0, "RULE");

        // Semantic analyzer blocks/hangs
        SecurityAnalyzer mockSemanticAnalyzer = new AISemanticSecurityAnalyzer(null, null) {
            @Override
            public SecurityAnalysisResult analyze(String content) {
                try {
                    // Sleep longer than the 150ms testProperties timeout
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    // Mock cancel/interrupted behaviour
                }
                return new SecurityAnalysisResult("LOW", 5, "NONE", "AI result", 0.95, "SEMANTIC");
            }
        };

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

        // Verify Rule HIGH 90 is retained, while AI timed out and returned SEMANTIC_UNAVAILABLE
        assertEquals(90, memory.getRiskScore());
        assertEquals("HIGH", memory.getRiskLevel());
        assertEquals("RULE_BLOCK", memory.getRiskCategory());
    }

    @Test
    void testAIAnalyzerExceptionDoesNotDiscardDeterministicResult() {
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("HIGH", 95, "RULE_BLOCK", "Rule matched", 1.0, "RULE");

        SecurityAnalyzer mockSemanticAnalyzer = new AISemanticSecurityAnalyzer(null, null) {
            @Override
            public SecurityAnalysisResult analyze(String content) {
                throw new AIServiceException(AIServiceException.FailureType.HTTP_ERROR, "Failed to connect to provider API_KEY_SECRET_123");
            }
        };

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

        // Verify Rule HIGH 95 is retained, while AI exception is gracefully handled
        assertEquals(95, memory.getRiskScore());
        assertEquals("HIGH", memory.getRiskLevel());
        assertEquals("RULE_BLOCK", memory.getRiskCategory());
    }

    @Test
    void testDeterministicAnalyzerFailurePropagated() {
        SecurityAnalyzer mockRuleAnalyzer = content -> {
            throw new RuntimeException("Deterministic rules database connection failed");
        };

        SecurityAnalyzer mockSemanticAnalyzer = new AISemanticSecurityAnalyzer(null, null) {
            @Override
            public SecurityAnalysisResult analyze(String content) {
                return new SecurityAnalysisResult("LOW", 10, "NONE", "AI result", 0.95, "SEMANTIC");
            }
        };

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

        // Verify that deterministic failure throws and is not converted to SAFE
        assertThrows(RuntimeException.class, () -> service.createMemory(memory));
    }
}

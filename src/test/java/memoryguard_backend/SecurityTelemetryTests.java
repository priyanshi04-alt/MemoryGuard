package memoryguard_backend;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.repository.SecurityLogRepository;
import memoryguard_backend.security.*;
import memoryguard_backend.service.MemoryService;
import memoryguard_backend.service.SecurityLogService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SecurityTelemetryTests {

    private ExecutorService testExecutor;
    private SecurityAnalysisProperties testProperties;
    private MemoryRepository memoryRepository;
    private SecurityLogRepository securityLogRepository;
    private SecurityLogService securityLogService;
    private PolicyEngine policyEngine;
    private RiskAggregator riskAggregator;

    @BeforeEach
    void setUp() {
        testProperties = new SecurityAnalysisProperties();
        testProperties.setParallelism(2);
        testProperties.setTimeoutMs(1000);
        testExecutor = Executors.newFixedThreadPool(2);

        memoryRepository = mock(MemoryRepository.class);
        securityLogRepository = mock(SecurityLogRepository.class);
        securityLogService = new SecurityLogService(securityLogRepository);
        policyEngine = new PolicyEngine();
        riskAggregator = new RiskAggregator();

        // Stub memory repository save to return the memory with an ID
        when(memoryRepository.save(any(Memory.class))).thenAnswer(invocation -> {
            Memory mem = invocation.getArgument(0);
            if (mem.getId() == null) {
                mem.setId(12345L);
            }
            return mem;
        });
    }

    @AfterEach
    void tearDown() {
        if (testExecutor != null) {
            testExecutor.shutdownNow();
        }
    }

    @Test
    void testSafeDecisionTelemetry() {
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("LOW", 10, "NONE", "Rule safe", 1.0, "RULE");

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
        memory.setContent("SAFE CONTENT");
        memory.setAgentId(1L);
        memory.setMemoryType("CORE");

        service.createMemory(memory);

        ArgumentCaptor<SecurityLog> logCaptor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository, times(1)).save(logCaptor.capture());

        SecurityLog log = logCaptor.getValue();
        assertNotNull(log);
        assertEquals(12345L, log.getMemoryId());
        assertEquals("ALLOWED", log.getActionTaken());
        assertEquals(10, log.getRiskScore());
        assertEquals("LOW", log.getRiskLevel());
        assertEquals("RULE", log.getAnalyzerType());
        assertNotNull(log.getCorrelationId());
    }

    @Test
    void testReviewDecisionTelemetry() {
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("MEDIUM", 55, "SQL_INJECTION", "Rule warning", 0.9, "RULE");

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
        memory.setContent("SELECT * FROM users");
        memory.setAgentId(1L);
        memory.setMemoryType("CORE");

        service.createMemory(memory);

        ArgumentCaptor<SecurityLog> logCaptor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository, times(1)).save(logCaptor.capture());

        SecurityLog log = logCaptor.getValue();
        assertNotNull(log);
        assertEquals(12345L, log.getMemoryId());
        assertEquals("REVIEW", log.getActionTaken());
        assertEquals(55, log.getRiskScore());
        assertEquals("MEDIUM", log.getRiskLevel());
        assertEquals("RULE", log.getAnalyzerType());
        assertEquals(0.9, log.getConfidence());
        assertEquals("SQL_INJECTION", log.getThreatType());
    }

    @Test
    void testBlockDecisionTelemetryAndCorrelationId() {
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("HIGH", 95, "PROMPT_INJECTION", "Rule block", 1.0, "RULE");

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
        memory.setContent("SECRET_MEMORY_PAYLOAD API_KEY_SECRET_123");
        memory.setAgentId(1L);
        memory.setMemoryType("CORE");

        service.createMemory(memory);

        // Blocked memories are NOT saved to memoryRepository
        verify(memoryRepository, never()).save(any(Memory.class));

        ArgumentCaptor<SecurityLog> logCaptor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository, times(1)).save(logCaptor.capture());

        SecurityLog log = logCaptor.getValue();
        assertNotNull(log);
        assertNull(log.getMemoryId()); // Blocked memoryId must be null
        assertEquals("BLOCKED", log.getActionTaken());
        assertEquals(95, log.getRiskScore());
        assertEquals("HIGH", log.getRiskLevel());
        assertEquals("RULE", log.getAnalyzerType());
        assertNotNull(log.getCorrelationId());
        assertEquals(memory.getCorrelationId(), log.getCorrelationId());
    }

    @Test
    void testAiHighRuleLowTelemetryCombination() {
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("LOW", 10, "NONE", "Rule low", 1.0, "RULE");
        SecurityAnalyzer mockSemanticAnalyzer = new AISemanticSecurityAnalyzer(null, null) {
            @Override
            public SecurityAnalysisResult analyze(String content) {
                return new SecurityAnalysisResult("HIGH", 85, "PROMPT_INJECTION", "AI high", 0.95, "SEMANTIC");
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
        memory.setContent("Test content");
        memory.setAgentId(1L);
        memory.setMemoryType("CORE");

        service.createMemory(memory);

        ArgumentCaptor<SecurityLog> logCaptor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository, times(1)).save(logCaptor.capture());

        SecurityLog log = logCaptor.getValue();
        assertNotNull(log);
        assertEquals("BLOCKED", log.getActionTaken());
        assertEquals(85, log.getRiskScore());
        assertEquals("HIGH", log.getRiskLevel());
        assertEquals("PROMPT_INJECTION", log.getThreatType());
        assertEquals("SEMANTIC", log.getAnalyzerType());
        assertEquals(0.95, log.getConfidence());
    }

    @Test
    void testRuleHighAiLowPreservesRuleTelemetry() {
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("HIGH", 90, "CREDENTIAL_LEAK", "Rule high", 1.0, "RULE");
        SecurityAnalyzer mockSemanticAnalyzer = new AISemanticSecurityAnalyzer(null, null) {
            @Override
            public SecurityAnalysisResult analyze(String content) {
                return new SecurityAnalysisResult("LOW", 10, "NONE", "AI low", 0.95, "SEMANTIC");
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
        memory.setContent("Test content");
        memory.setAgentId(1L);
        memory.setMemoryType("CORE");

        service.createMemory(memory);

        ArgumentCaptor<SecurityLog> logCaptor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository, times(1)).save(logCaptor.capture());

        SecurityLog log = logCaptor.getValue();
        assertNotNull(log);
        assertEquals("BLOCKED", log.getActionTaken());
        assertEquals(90, log.getRiskScore());
        assertEquals("HIGH", log.getRiskLevel());
        assertEquals("CREDENTIAL_LEAK", log.getThreatType());
        assertEquals("RULE", log.getAnalyzerType());
        assertEquals(1.0, log.getConfidence());
    }

    @Test
    void testAiUnavailableDoesNotBecomeFakeLowTelemetry() {
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("MEDIUM", 50, "NONE", "Rule mid", 1.0, "RULE");
        SecurityAnalyzer mockSemanticAnalyzer = new AISemanticSecurityAnalyzer(null, null) {
            @Override
            public SecurityAnalysisResult analyze(String content) {
                return new SecurityAnalysisResult("LOW", 0, "SEMANTIC_UNAVAILABLE", "AI failed", 0.0, "SEMANTIC");
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
        memory.setContent("Test content");
        memory.setAgentId(1L);
        memory.setMemoryType("CORE");

        service.createMemory(memory);

        ArgumentCaptor<SecurityLog> logCaptor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository, times(1)).save(logCaptor.capture());

        SecurityLog log = logCaptor.getValue();
        assertNotNull(log);
        assertEquals("REVIEW", log.getActionTaken());
        assertEquals(50, log.getRiskScore());
        assertEquals("MEDIUM", log.getRiskLevel());
        assertEquals("RULE", log.getAnalyzerType());
    }

    @Test
    void testSensitivePrivacyDataExclusion() {
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("HIGH", 95, "PROMPT_INJECTION", "Rule block", 1.0, "RULE");

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
        // Set sensitive strings in memory content
        String rawContent = "SECRET_MEMORY_PAYLOAD and API_KEY_SECRET_123 and RAW_GEMINI_RESPONSE";
        memory.setContent(rawContent);
        memory.setAgentId(1L);
        memory.setMemoryType("CORE");

        service.createMemory(memory);

        ArgumentCaptor<SecurityLog> logCaptor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository, times(1)).save(logCaptor.capture());

        SecurityLog log = logCaptor.getValue();
        assertNotNull(log);

        // Convert the log fields to string representation to verify no leak
        String stringLog = String.format("%s %s %s %s %d %s", 
                log.getThreatType(), 
                log.getActionTaken(), 
                log.getAnalyzerType(), 
                log.getRiskLevel(),
                log.getRiskScore(),
                log.getCorrelationId());

        assertFalse(stringLog.contains("SECRET_MEMORY_PAYLOAD"));
        assertFalse(stringLog.contains("API_KEY_SECRET_123"));
        assertFalse(stringLog.contains("RAW_GEMINI_RESPONSE"));
    }

    @Test
    void testClientCannotForgeTelemetry() {
        SecurityAnalyzer mockRuleAnalyzer = content -> new SecurityAnalysisResult("LOW", 10, "NONE", "Rule safe", 1.0, "RULE");

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
        memory.setContent("SAFE CONTENT");
        memory.setAgentId(1L);
        memory.setMemoryType("CORE");
        
        // Client attempts to forge properties:
        memory.setRiskScore(99);
        memory.setRiskLevel("HIGH");
        memory.setRiskCategory("MALWARE");
        memory.setStatus("BLOCKED");
        memory.setCorrelationId("hacked-id-123");

        service.createMemory(memory);

        ArgumentCaptor<SecurityLog> logCaptor = ArgumentCaptor.forClass(SecurityLog.class);
        verify(securityLogRepository, times(1)).save(logCaptor.capture());

        SecurityLog log = logCaptor.getValue();
        assertNotNull(log);
        
        // Assert that client-forged correlationId is overwritten:
        assertNotEquals("hacked-id-123", log.getCorrelationId());
        assertNotEquals("hacked-id-123", memory.getCorrelationId());
        assertEquals(memory.getCorrelationId(), log.getCorrelationId());

        // Assert that riskScore and level are calculated and overwritten:
        assertEquals(10, log.getRiskScore());
        assertEquals("LOW", log.getRiskLevel());
        assertEquals("NONE", log.getThreatType());
        
        // Status is ALLOWED, not BLOCKED:
        assertEquals("ALLOWED", log.getActionTaken());
    }
}

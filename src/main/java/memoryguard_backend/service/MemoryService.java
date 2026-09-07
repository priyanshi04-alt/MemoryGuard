package memoryguard_backend.service;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.repository.QuarantinedMemoryRepository;
import memoryguard_backend.repository.DeniedMemoryRepository;
import memoryguard_backend.security.*;
import memoryguard_backend.security.context.ContextAnalysisResult;
import memoryguard_backend.security.context.ContextAnalyzer;
import memoryguard_backend.security.persistence.PersistenceResult;

import memoryguard_backend.security.signals.SecuritySignalExtractor;
import memoryguard_backend.security.signals.SecuritySignals;
import memoryguard_backend.security.content.MemoryContentAnalyzer;
import memoryguard_backend.security.content.ContentAnalysisResult;
import memoryguard_backend.security.content.ContentSecuritySignal;
import memoryguard_backend.security.risk.MemoryRiskAggregator;
import memoryguard_backend.security.risk.MemoryRiskAssessment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class MemoryService {

    private final MemoryRepository memoryRepository;
    private final List<SecurityAnalyzer> securityAnalyzers;
    private final ProvenanceAnalyzer provenanceAnalyzer;
    private final ContextAnalyzer contextAnalyzer;
    private final SecuritySignalExtractor securitySignalExtractor;
    private final MemoryContentAnalyzer memoryContentAnalyzer;
    private final MemoryRiskAggregator memoryRiskAggregator;
    private final SecurityLogService securityLogService;
    private final PolicyEngine policyEngine;
    private final RiskAggregator riskAggregator;
    private final MemoryPersistenceService memoryPersistenceService;
    private final ExecutorService securityAnalysisExecutor;
    private final SecurityAnalysisProperties securityAnalysisProperties;

    @Autowired
    public MemoryService(
            MemoryRepository memoryRepository,
            List<SecurityAnalyzer> securityAnalyzers,
            ProvenanceAnalyzer provenanceAnalyzer,
            ContextAnalyzer contextAnalyzer,
            SecuritySignalExtractor securitySignalExtractor,
            MemoryContentAnalyzer memoryContentAnalyzer,
            MemoryRiskAggregator memoryRiskAggregator,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine,
            RiskAggregator riskAggregator,
            MemoryPersistenceService memoryPersistenceService,
            ExecutorService securityAnalysisExecutor,
            SecurityAnalysisProperties securityAnalysisProperties) {

        this.memoryRepository = memoryRepository;
        this.securityAnalyzers = securityAnalyzers != null ? securityAnalyzers : List.of();
        this.provenanceAnalyzer = provenanceAnalyzer != null ? provenanceAnalyzer : new ProvenanceAnalyzer();
        this.contextAnalyzer = contextAnalyzer != null ? contextAnalyzer : new ContextAnalyzer();
        this.securitySignalExtractor = securitySignalExtractor != null ? securitySignalExtractor : new SecuritySignalExtractor();
        this.memoryContentAnalyzer = memoryContentAnalyzer != null ? memoryContentAnalyzer : new MemoryContentAnalyzer();
        this.memoryRiskAggregator = memoryRiskAggregator != null ? memoryRiskAggregator : new MemoryRiskAggregator();
        this.securityLogService = securityLogService;
        this.policyEngine = policyEngine != null ? policyEngine : new PolicyEngine();
        this.riskAggregator = riskAggregator != null ? riskAggregator : new RiskAggregator();
        this.memoryPersistenceService = memoryPersistenceService != null ? memoryPersistenceService :
                new MemoryPersistenceService(memoryRepository, null, null, securityLogService);
        this.securityAnalysisExecutor = securityAnalysisExecutor != null ? securityAnalysisExecutor : Executors.newFixedThreadPool(2);
        this.securityAnalysisProperties = securityAnalysisProperties != null ? securityAnalysisProperties : new SecurityAnalysisProperties();
    }

    public MemoryService(
            MemoryRepository memoryRepository,
            List<SecurityAnalyzer> securityAnalyzers,
            ProvenanceAnalyzer provenanceAnalyzer,
            ContextAnalyzer contextAnalyzer,
            SecuritySignalExtractor securitySignalExtractor,
            MemoryContentAnalyzer memoryContentAnalyzer,
            MemoryRiskAggregator memoryRiskAggregator,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine,
            RiskAggregator riskAggregator,
            ExecutorService securityAnalysisExecutor,
            SecurityAnalysisProperties securityAnalysisProperties) {

        this(
                memoryRepository,
                securityAnalyzers,
                provenanceAnalyzer,
                contextAnalyzer,
                securitySignalExtractor,
                memoryContentAnalyzer,
                memoryRiskAggregator,
                securityLogService,
                policyEngine,
                riskAggregator,
                null,
                securityAnalysisExecutor,
                securityAnalysisProperties
        );
    }

    public MemoryService(
            MemoryRepository memoryRepository,
            List<SecurityAnalyzer> securityAnalyzers,
            ProvenanceAnalyzer provenanceAnalyzer,
            SecuritySignalExtractor securitySignalExtractor,
            MemoryContentAnalyzer memoryContentAnalyzer,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine,
            RiskAggregator riskAggregator,
            ExecutorService securityAnalysisExecutor,
            SecurityAnalysisProperties securityAnalysisProperties) {

        this(
                memoryRepository,
                securityAnalyzers,
                provenanceAnalyzer,
                new ContextAnalyzer(),
                securitySignalExtractor,
                memoryContentAnalyzer,
                new MemoryRiskAggregator(),
                securityLogService,
                policyEngine,
                riskAggregator,
                null,
                securityAnalysisExecutor,
                securityAnalysisProperties
        );
    }

    public MemoryService(
            MemoryRepository memoryRepository,
            List<SecurityAnalyzer> securityAnalyzers,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine,
            RiskAggregator riskAggregator,
            ExecutorService securityAnalysisExecutor,
            SecurityAnalysisProperties securityAnalysisProperties) {

        this(
                memoryRepository,
                securityAnalyzers,
                new ProvenanceAnalyzer(),
                new ContextAnalyzer(),
                new SecuritySignalExtractor(),
                new MemoryContentAnalyzer(),
                new MemoryRiskAggregator(),
                securityLogService,
                policyEngine,
                riskAggregator,
                null,
                securityAnalysisExecutor,
                securityAnalysisProperties
        );
    }

    // ============================================================
    // GET ALL MEMORIES (ACTIVE / SAFE ONLY)
    // ============================================================

    public List<Memory> getAllMemories() {
        return getMemoriesByStatus("SAFE");
    }

    public List<Memory> getMemoriesByStatus(String status) {

        List<Memory> memories;

        if ("ALL".equalsIgnoreCase(status)) {
            memories = memoryRepository.findAll();
        } else {
            memories = memoryRepository.findByStatus(status.toUpperCase());
        }

        for (Memory memory : memories) {
            analyzeRisk(memory);
        }

        return memories;
    }

    // ============================================================
    // GET MEMORY BY ID
    // ============================================================

    public Optional<Memory> getMemoryById(Long id) {

        Optional<Memory> memory = memoryRepository.findById(id);

        if (memory.isPresent()) {
            analyzeRisk(memory.get());
        }

        return memory;
    }

    // ============================================================
    // VERIFY MEMORY INTEGRITY
    // ============================================================

    public boolean verifyIntegrity(Memory memory) {

        String calculatedHash = HashUtil.generateHash(memory.getContent());

        return calculatedHash.equals(memory.getIntegrityHash());
    }

    // ============================================================
    // CONTENT & RISK ANALYSIS HELPERS
    // ============================================================

    public ContentAnalysisResult analyzeContent(String content) {
        return memoryContentAnalyzer.analyze(content);
    }

    public ContentAnalysisResult analyzeContent(Memory memory) {
        if (memory == null) {
            throw new IllegalArgumentException("Memory request cannot be null");
        }
        return memoryContentAnalyzer.analyze(memory.getContent());
    }

    public MemoryRiskAssessment assessRisk(ContentAnalysisResult contentAnalysisResult) {
        return memoryRiskAggregator.aggregate(contentAnalysisResult);
    }

    public MemoryRiskAssessment assessRisk(List<ContentSecuritySignal> signals) {
        return memoryRiskAggregator.aggregate(signals);
    }

    public MemoryRiskAssessment assessRisk(String content) {
        ContentAnalysisResult contentResult = analyzeContent(content);
        return memoryRiskAggregator.aggregate(contentResult);
    }

    public MemoryRiskAssessment assessRisk(Memory memory) {
        if (memory == null) {
            throw new IllegalArgumentException("Memory request cannot be null");
        }
        return assessRisk(memory.getContent());
    }

    public SecuritySignals extractSecuritySignals(Memory memory) {
        if (memory == null) {
            throw new IllegalArgumentException("Memory request cannot be null");
        }
        return securitySignalExtractor.extract(memory);
    }

    public Optional<SecuritySignals> extractSecuritySignals(Long id) {
        return memoryRepository.findById(id)
                .map(securitySignalExtractor::extract);
    }

    // ============================================================
    // MEMORY GATEWAY VALIDATION
    // ============================================================

    private void validateIncomingMemory(Memory memory) {

        if (memory == null) {
            throw new IllegalArgumentException("Memory request cannot be null");
        }

        if (memory.getContent() == null || memory.getContent().trim().isEmpty()) {
            throw new IllegalArgumentException("Memory content cannot be empty");
        }

        if (memory.getContent().length() > 10000) {
            throw new IllegalArgumentException("Memory content exceeds maximum allowed size");
        }
    }

    // ============================================================
    // CREATE MEMORY PIPELINE (DAY 22 PERSISTENCE ENFORCEMENT)
    // ============================================================

    public Memory createMemory(Memory memory) {

        // 0. Gateway Validation
        validateIncomingMemory(memory);

        // 1. Identifiers & Integrity Hashing
        String correlationId = java.util.UUID.randomUUID().toString();
        memory.setCorrelationId(correlationId);
        String hash = HashUtil.generateHash(memory.getContent());
        memory.setIntegrityHash(hash);

        // 2. Provenance Analysis
        ProvenanceAnalysisResult provenanceResult = provenanceAnalyzer.analyze(memory);

        // 3. Context Analysis
        ContextAnalysisResult contextResult = contextAnalyzer.analyze(memory);

        // 4. Security Analyzers (Parallel execution across detectors)
        AggregatedRiskAssessment riskAssessment = analyzeRiskAssessment(memory, provenanceResult, contextResult);

        // Populate Memory risk attributes
        memory.setRiskLevel(riskAssessment.getOverallRiskLevel());
        memory.setRiskScore(riskAssessment.getOverallRiskScore());
        memory.setRiskCategory(riskAssessment.getPrimaryCategory());

        // 5. Policy Engine Evaluation
        PolicyDecisionResult policyResult = policyEngine.evaluate(riskAssessment);
        memory.setRiskReason(policyResult.getExplanation());

        // 6. Persistence Enforcement Service (ALLOW -> PERMITTED, REVIEW -> QUARANTINED, BLOCK -> DENIED)
        PersistenceResult persistenceResult = memoryPersistenceService.enforcePersistence(memory, policyResult, riskAssessment);

        if (persistenceResult.isPermitted()) {
            memory.setStatus("SAFE");
            if (persistenceResult.getMemoryId() != null) {
                memory.setId(persistenceResult.getMemoryId());
            }
        } else if (persistenceResult.isQuarantined()) {
            memory.setStatus("REVIEW");
            if (persistenceResult.getQuarantineId() != null) {
                memory.setId(persistenceResult.getQuarantineId());
            }
        } else {
            memory.setStatus("BLOCKED");
            memory.setId(null);
        }

        return memory;
    }

    // ============================================================
    // RISK ASSESSMENT EXECUTION
    // ============================================================

    private SecurityAnalysisResult analyzeRisk(Memory memory) {
        ProvenanceAnalysisResult provenanceResult = provenanceAnalyzer.analyze(memory);
        ContextAnalysisResult contextResult = contextAnalyzer.analyze(memory);
        AggregatedRiskAssessment assessment = analyzeRiskAssessment(memory, provenanceResult, contextResult);

        memory.setRiskLevel(assessment.getOverallRiskLevel());
        memory.setRiskScore(assessment.getOverallRiskScore());
        memory.setRiskCategory(assessment.getPrimaryCategory());
        memory.setRiskReason(assessment.getPrimaryReason());

        return new SecurityAnalysisResult(
                assessment.getOverallRiskLevel(),
                assessment.getOverallRiskScore(),
                assessment.getPrimaryCategory(),
                assessment.getPrimaryReason(),
                assessment.getConfidence(),
                "AGGREGATED"
        );
    }

    private AggregatedRiskAssessment analyzeRiskAssessment(
            Memory memory,
            ProvenanceAnalysisResult provenanceResult,
            ContextAnalysisResult contextResult) {

        List<java.util.concurrent.Future<SecurityAnalysisResult>> futures = new java.util.ArrayList<>();

        for (SecurityAnalyzer analyzer : securityAnalyzers) {
            futures.add(
                    securityAnalysisExecutor.submit(
                            () -> analyzer.analyze(memory.getContent())
                    )
            );
        }

        List<SecurityAnalysisResult> results = new java.util.ArrayList<>();

        for (int i = 0; i < securityAnalyzers.size(); i++) {
            SecurityAnalyzer analyzer = securityAnalyzers.get(i);
            java.util.concurrent.Future<SecurityAnalysisResult> future = futures.get(i);

            try {
                SecurityAnalysisResult res = future.get(
                        securityAnalysisProperties.getTimeoutMs(),
                        java.util.concurrent.TimeUnit.MILLISECONDS
                );
                results.add(res);
            } catch (java.util.concurrent.TimeoutException e) {
                future.cancel(true);
                if (!"SEMANTIC".equals(analyzer.getAnalyzerType())) {
                    throw new RuntimeException("Deterministic security analysis timed out", e);
                } else {
                    results.add(createUnavailableResult("AI Semantic analysis timed out"));
                }
            } catch (Exception e) {
                if (!"SEMANTIC".equals(analyzer.getAnalyzerType())) {
                    throw new RuntimeException("Security analysis failed", e);
                } else {
                    results.add(createUnavailableResult("AI Semantic analysis failed"));
                }
            }
        }

        if (memoryContentAnalyzer != null && memory.getContent() != null) {
            ContentAnalysisResult contentResult = memoryContentAnalyzer.analyze(memory.getContent());
            if (contentResult != null && contentResult.getSignals() != null) {
                for (ContentSecuritySignal sig : contentResult.getSignals()) {
                    int score = mapSeverityToScore(sig.getSeverity());
                    results.add(new SecurityAnalysisResult(
                            mapScoreToLevel(score),
                            score,
                            sig.getType(),
                            sig.getDescription() != null ? sig.getDescription() : "Content threat signal detected",
                            0.9,
                            "RULE"
                    ));
                }
            }
        }

        if (provenanceResult != null) {
            results.add(provenanceResult);
        }

        if (contextResult != null && contextResult.getRiskScore() > 0) {
            results.add(contextAnalyzer.toSecurityAnalysisResult(contextResult));
        }

        return riskAggregator.aggregateAssessment(results);
    }

    private int mapSeverityToScore(String severity) {
        if (severity == null) return 50;
        switch (severity.toUpperCase().trim()) {
            case "CRITICAL": return 100;
            case "HIGH": return 85;
            case "MEDIUM": return 55;
            case "LOW": return 20;
            default: return 50;
        }
    }

    private String mapScoreToLevel(int score) {
        if (score >= 80) return "HIGH";
        if (score >= 50) return "MEDIUM";
        return "LOW";
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

    // ============================================================
    // MEMORY STATISTICS
    // ============================================================

    public memoryguard_backend.controller.MemoryController.MemoryStats getMemoryStats() {

        long totalTrusted = memoryRepository.countByStatus("SAFE");
        long needsReview = memoryRepository.countByStatus("REVIEW");
        long blockedAttempts = securityLogService.countByAction("BLOCKED") + securityLogService.countByAction("MEMORY_DENIED");

        return new memoryguard_backend.controller.MemoryController.MemoryStats(
                totalTrusted,
                blockedAttempts,
                needsReview,
                new memoryguard_backend.controller.MemoryController.RiskDistribution(
                        totalTrusted,
                        needsReview,
                        blockedAttempts
                )
        );
    }
}
package memoryguard_backend.service;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.security.HashUtil;
import memoryguard_backend.security.PolicyDecision;
import memoryguard_backend.security.PolicyEngine;
import memoryguard_backend.security.ProvenanceAnalysisResult;
import memoryguard_backend.security.ProvenanceAnalyzer;
import memoryguard_backend.security.RiskAggregator;
import memoryguard_backend.security.SecurityAnalysisResult;
import memoryguard_backend.security.SecurityAnalyzer;
import memoryguard_backend.security.SecurityAnalysisProperties;

import memoryguard_backend.security.signals.SecuritySignalExtractor;
import memoryguard_backend.security.signals.SecuritySignals;
import memoryguard_backend.security.content.MemoryContentAnalyzer;
import memoryguard_backend.security.content.ContentAnalysisResult;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;

@Service
public class MemoryService {

    private final MemoryRepository memoryRepository;
    private final List<SecurityAnalyzer> securityAnalyzers;
    private final ProvenanceAnalyzer provenanceAnalyzer;
    private final SecuritySignalExtractor securitySignalExtractor;
    private final MemoryContentAnalyzer memoryContentAnalyzer;
    private final SecurityLogService securityLogService;
    private final PolicyEngine policyEngine;
    private final RiskAggregator riskAggregator;
    private final ExecutorService securityAnalysisExecutor;
    private final SecurityAnalysisProperties securityAnalysisProperties;

    @Autowired
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

        this.memoryRepository = memoryRepository;
        this.securityAnalyzers = securityAnalyzers;
        this.provenanceAnalyzer = provenanceAnalyzer;
        this.securitySignalExtractor = securitySignalExtractor != null ? securitySignalExtractor : new SecuritySignalExtractor();
        this.memoryContentAnalyzer = memoryContentAnalyzer != null ? memoryContentAnalyzer : new MemoryContentAnalyzer();
        this.securityLogService = securityLogService;
        this.policyEngine = policyEngine;
        this.riskAggregator = riskAggregator;
        this.securityAnalysisExecutor = securityAnalysisExecutor;
        this.securityAnalysisProperties = securityAnalysisProperties;
    }

    public MemoryService(
            MemoryRepository memoryRepository,
            List<SecurityAnalyzer> securityAnalyzers,
            ProvenanceAnalyzer provenanceAnalyzer,
            SecuritySignalExtractor securitySignalExtractor,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine,
            RiskAggregator riskAggregator,
            ExecutorService securityAnalysisExecutor,
            SecurityAnalysisProperties securityAnalysisProperties) {

        this(
                memoryRepository,
                securityAnalyzers,
                provenanceAnalyzer,
                securitySignalExtractor,
                new MemoryContentAnalyzer(),
                securityLogService,
                policyEngine,
                riskAggregator,
                securityAnalysisExecutor,
                securityAnalysisProperties
        );
    }

    public MemoryService(
            MemoryRepository memoryRepository,
            List<SecurityAnalyzer> securityAnalyzers,
            ProvenanceAnalyzer provenanceAnalyzer,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine,
            RiskAggregator riskAggregator,
            ExecutorService securityAnalysisExecutor,
            SecurityAnalysisProperties securityAnalysisProperties) {

        this(
                memoryRepository,
                securityAnalyzers,
                provenanceAnalyzer,
                new SecuritySignalExtractor(),
                new MemoryContentAnalyzer(),
                securityLogService,
                policyEngine,
                riskAggregator,
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
                new SecuritySignalExtractor(),
                new MemoryContentAnalyzer(),
                securityLogService,
                policyEngine,
                riskAggregator,
                securityAnalysisExecutor,
                securityAnalysisProperties
        );
    }

    // ============================================================
    // GET ALL MEMORIES
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

        Optional<Memory> memory =
                memoryRepository.findById(id);

        if (memory.isPresent()) {
            analyzeRisk(memory.get());
        }

        return memory;
    }

    // ============================================================
    // VERIFY MEMORY INTEGRITY
    // ============================================================

    public boolean verifyIntegrity(Memory memory) {

        String calculatedHash =
                HashUtil.generateHash(
                        memory.getContent()
                );

        return calculatedHash.equals(
                memory.getIntegrityHash()
        );
    }

    // ============================================================
    // DAY 17 - MEMORY CONTENT SECURITY ANALYSIS
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

    // ============================================================
    // DAY 19 - SECURITY SIGNAL EXTRACTION
    // ============================================================

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
            throw new IllegalArgumentException(
                    "Memory request cannot be null"
            );
        }

        if (memory.getContent() == null ||
                memory.getContent().trim().isEmpty()) {

            throw new IllegalArgumentException(
                    "Memory content cannot be empty"
            );
        }

        if (memory.getContent().length() > 10000) {

            throw new IllegalArgumentException(
                    "Memory content exceeds maximum allowed size"
            );
        }
    }

    // ============================================================
    // CREATE MEMORY
    // ============================================================

    public Memory createMemory(Memory memory) {

        // ========================================================
        // 0. MEMORY GATEWAY VALIDATION
        // ========================================================

        validateIncomingMemory(memory);

        // ========================================================
        // 0.5. MEMORY CONTENT SECURITY ANALYSIS (DAY 17)
        // ========================================================

        ContentAnalysisResult contentAnalysisResult =
                memoryContentAnalyzer.analyze(memory.getContent());

        // ========================================================
        // 1. GENERATE CORRELATION ID
        // ========================================================

        String correlationId =
                java.util.UUID.randomUUID().toString();

        memory.setCorrelationId(correlationId);

        // ========================================================
        // 2. GENERATE INTEGRITY HASH
        // ========================================================

        String hash =
                HashUtil.generateHash(
                        memory.getContent()
                );

        memory.setIntegrityHash(hash);

        // ========================================================
        // 3. PROVENANCE ANALYSIS
        // ========================================================

        ProvenanceAnalysisResult provenanceResult =
                provenanceAnalyzer.analyze(memory);

        // ========================================================
        // 3.5. SECURITY SIGNAL EXTRACTION (DAY 19)
        // ========================================================

        SecuritySignals securitySignals =
                securitySignalExtractor.extract(memory);

        // ========================================================
        // 4. SECURITY ANALYSIS
        // ========================================================

        SecurityAnalysisResult analysisResult =
                analyzeRisk(memory, provenanceResult);

        // ========================================================
        // 5. POLICY DECISION
        // ========================================================

        PolicyDecision decision =
                policyEngine.decide(
                        memory.getRiskScore()
                );

        // ========================================================
        // 6. BLOCK HIGH-RISK MEMORY
        // ========================================================

        if (decision == PolicyDecision.BLOCK) {

            memory.setStatus("BLOCKED");

            SecurityLog log =
                    new SecurityLog();

            // Blocked memory is not persisted,
            // therefore it has no database memory ID.

            log.setMemoryId(null);
            log.setCorrelationId(correlationId);

            log.setRiskScore(
                    memory.getRiskScore()
            );

            log.setThreatType(
                    memory.getRiskCategory()
            );

            log.setActionTaken("BLOCKED");
            log.setRiskLevel(
                    memory.getRiskLevel()
            );

            log.setConfidence(
                    analysisResult.getConfidence()
            );

            log.setAnalyzerType(
                    analysisResult.getAnalyzerType()
            );

            log.setProvenance(
                    memory.getProvenance() != null
                            ? memory.getProvenance().name()
                            : "UNKNOWN"
            );

            securityLogService.save(log);

            return memory;
        }

        // ========================================================
        // 7. REVIEW MEDIUM-RISK MEMORY
        // ========================================================

        if (decision == PolicyDecision.REVIEW) {

            memory.setStatus("REVIEW");

            Memory savedMemory =
                    memoryRepository.save(memory);

            Long memoryId =
                    (savedMemory != null)
                            ? savedMemory.getId()
                            : null;

            SecurityLog log =
                    new SecurityLog();

            log.setMemoryId(memoryId);
            log.setCorrelationId(correlationId);

            log.setRiskScore(
                    savedMemory != null
                            ? savedMemory.getRiskScore()
                            : memory.getRiskScore()
            );

            log.setThreatType(
                    savedMemory != null
                            ? savedMemory.getRiskCategory()
                            : memory.getRiskCategory()
            );

            log.setActionTaken("REVIEW");

            log.setRiskLevel(
                    savedMemory != null
                            ? savedMemory.getRiskLevel()
                            : memory.getRiskLevel()
            );

            log.setConfidence(
                    analysisResult.getConfidence()
            );

            log.setAnalyzerType(
                    analysisResult.getAnalyzerType()
            );

            log.setProvenance(
                    savedMemory != null && savedMemory.getProvenance() != null
                            ? savedMemory.getProvenance().name()
                            : (memory.getProvenance() != null ? memory.getProvenance().name() : "UNKNOWN")
            );

            securityLogService.save(log);

            return savedMemory != null
                    ? savedMemory
                    : memory;
        }

        // ========================================================
        // 8. ALLOW LOW-RISK MEMORY
        // ========================================================

        memory.setStatus("SAFE");

        Memory savedMemory =
                memoryRepository.save(memory);

        Long memoryId =
                (savedMemory != null)
                        ? savedMemory.getId()
                        : null;

        SecurityLog log =
                new SecurityLog();

        log.setMemoryId(memoryId);
        log.setCorrelationId(correlationId);

        log.setRiskScore(
                savedMemory != null
                        ? savedMemory.getRiskScore()
                        : memory.getRiskScore()
        );

        log.setThreatType(
                savedMemory != null
                        ? savedMemory.getRiskCategory()
                        : memory.getRiskCategory()
        );

        log.setActionTaken("ALLOWED");

        log.setRiskLevel(
                savedMemory != null
                        ? savedMemory.getRiskLevel()
                        : memory.getRiskLevel()
        );

        log.setConfidence(
                analysisResult.getConfidence()
        );

        log.setAnalyzerType(
                analysisResult.getAnalyzerType()
        );

        log.setProvenance(
                savedMemory != null && savedMemory.getProvenance() != null
                        ? savedMemory.getProvenance().name()
                        : (memory.getProvenance() != null ? memory.getProvenance().name() : "UNKNOWN")
        );

        securityLogService.save(log);

        return savedMemory != null
                ? savedMemory
                : memory;
    }

    // ============================================================
    // SECURITY ANALYSIS
    // ============================================================

    private SecurityAnalysisResult analyzeRisk(Memory memory) {
        ProvenanceAnalysisResult provenanceResult =
                provenanceAnalyzer.analyze(memory);

        return analyzeRisk(memory, provenanceResult);
    }

    private SecurityAnalysisResult analyzeRisk(
            Memory memory,
            ProvenanceAnalysisResult provenanceResult) {

        List<java.util.concurrent.Future<SecurityAnalysisResult>>
                futures = new java.util.ArrayList<>();

        for (SecurityAnalyzer analyzer : securityAnalyzers) {

            futures.add(
                    securityAnalysisExecutor.submit(
                            () -> analyzer.analyze(
                                    memory.getContent()
                            )
                    )
            );
        }

        List<SecurityAnalysisResult> results =
                new java.util.ArrayList<>();

        for (int i = 0;
             i < securityAnalyzers.size();
             i++) {

            SecurityAnalyzer analyzer =
                    securityAnalyzers.get(i);

            java.util.concurrent.Future<SecurityAnalysisResult>
                    future = futures.get(i);

            try {

                SecurityAnalysisResult res =
                        future.get(
                                securityAnalysisProperties
                                        .getTimeoutMs(),
                                java.util.concurrent.TimeUnit.MILLISECONDS
                        );

                results.add(res);

            } catch (
                    java.util.concurrent.TimeoutException e) {

                future.cancel(true);

                if (!"SEMANTIC".equals(
                        analyzer.getAnalyzerType())) {

                    throw new RuntimeException(
                            "Deterministic security analysis timed out",
                            e
                    );

                } else {

                    results.add(
                            createUnavailableResult(
                                     "AI Semantic analysis timed out"
                            )
                    );
                }

            } catch (
                    java.util.concurrent.ExecutionException e) {

                if (!"SEMANTIC".equals(
                        analyzer.getAnalyzerType())) {

                    throw new RuntimeException(
                            "Deterministic security analysis failed",
                            e.getCause()
                    );

                } else {

                    results.add(
                            createUnavailableResult(
                                    "AI Semantic analysis failed"
                            )
                    );
                }

            } catch (Exception e) {

                if (!"SEMANTIC".equals(
                        analyzer.getAnalyzerType())) {

                    throw new RuntimeException(
                            "Deterministic security analysis interrupted or failed",
                            e
                    );

                } else {

                    results.add(
                            createUnavailableResult(
                                    "AI Semantic analysis failed"
                            )
                    );
                }
            }
        }

        // Add provenance security analysis signal
        if (provenanceResult != null) {
            results.add(provenanceResult);
        }

        SecurityAnalysisResult result =
                riskAggregator.aggregate(results);

        // ========================================================
        // RISK LEVEL
        // ========================================================

        memory.setRiskLevel(
                result.getRiskLevel()
        );

        // ========================================================
        // RISK SCORE
        // ========================================================

        memory.setRiskScore(
                result.getRiskScore()
        );

        // ========================================================
        // THREAT CATEGORY
        // ========================================================

        memory.setRiskCategory(
                result.getCategory()
        );

        // ========================================================
        // EXPLANATION
        // ========================================================

        memory.setRiskReason(
                result.getReason()
        );

        return result;
    }

    // ============================================================
    // SEMANTIC ANALYSIS FALLBACK
    // ============================================================

    private SecurityAnalysisResult createUnavailableResult(
            String reason) {

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

    public memoryguard_backend.controller.MemoryController.MemoryStats
    getMemoryStats() {

        long totalTrusted =
                memoryRepository.countByStatus("SAFE");

        long needsReview =
                memoryRepository.countByStatus("REVIEW");

        long blockedAttempts =
                securityLogService.countByAction("BLOCKED");

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
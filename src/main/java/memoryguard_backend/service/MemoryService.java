package memoryguard_backend.service;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.security.HashUtil;
import memoryguard_backend.security.PolicyDecision;
import memoryguard_backend.security.PolicyEngine;
import memoryguard_backend.security.RiskAggregator;
import memoryguard_backend.security.SecurityAnalysisResult;
import memoryguard_backend.security.SecurityAnalyzer;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class MemoryService {

    private final MemoryRepository memoryRepository;
    private final SecurityAnalyzer securityAnalyzer;
    private final SecurityLogService securityLogService;
    private final PolicyEngine policyEngine;
    private final RiskAggregator riskAggregator;

    public MemoryService(
            MemoryRepository memoryRepository,
            SecurityAnalyzer securityAnalyzer,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine,
            RiskAggregator riskAggregator) {

        this.memoryRepository = memoryRepository;
        this.securityAnalyzer = securityAnalyzer;
        this.securityLogService = securityLogService;
        this.policyEngine = policyEngine;
        this.riskAggregator = riskAggregator;
    }


    // ============================================================
    // GET ALL MEMORIES
    // ============================================================

    public List<Memory> getAllMemories() {

        List<Memory> memories =
                memoryRepository.findAll();

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
    // CREATE MEMORY
    // ============================================================

    public Memory createMemory(Memory memory) {

        // ========================================================
        // 1. GENERATE INTEGRITY HASH
        // ========================================================

        String hash =
                HashUtil.generateHash(
                        memory.getContent()
                );

        memory.setIntegrityHash(hash);


        // ========================================================
        // 2. SECURITY ANALYSIS
        // ========================================================

        analyzeRisk(memory);


        // ========================================================
        // 3. POLICY DECISION
        // ========================================================

        PolicyDecision decision =
                policyEngine.decide(
                        memory.getRiskScore()
                );


        // ========================================================
        // 4. BLOCK HIGH-RISK MEMORY
        // ========================================================

        if (decision == PolicyDecision.BLOCK) {

            memory.setStatus("BLOCKED");

            SecurityLog log =
                    new SecurityLog();

            // Blocked memory is not persisted,
            // therefore it has no database memory ID.

            log.setMemoryId(null);

            log.setRiskScore(
                    memory.getRiskScore()
            );

            log.setThreatType(
                    memory.getRiskCategory()
            );

            log.setActionTaken("BLOCKED");

            securityLogService.save(log);

            return memory;
        }


        // ========================================================
        // 5. REVIEW MEDIUM-RISK MEMORY
        // ========================================================

        if (decision == PolicyDecision.REVIEW) {

            memory.setStatus("REVIEW");

            return memoryRepository.save(memory);
        }


        // ========================================================
        // 6. ALLOW LOW-RISK MEMORY
        // ========================================================

        memory.setStatus("SAFE");

        return memoryRepository.save(memory);
    }


    // ============================================================
    // SECURITY ANALYSIS
    // ============================================================

    private void analyzeRisk(Memory memory) {

        SecurityAnalysisResult ruleResult =
                securityAnalyzer.analyze(
                        memory.getContent()
                );

        SecurityAnalysisResult result =
                riskAggregator.aggregate(
                        List.of(ruleResult)
                );


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
    }
}
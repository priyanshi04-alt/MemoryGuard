package memoryguard_backend.service;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.SecurityLog;

import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.security.HashUtil;
import memoryguard_backend.security.MemoryRiskAnalyzer;
import memoryguard_backend.security.PolicyDecision;
import memoryguard_backend.security.PolicyEngine;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class MemoryService {

    private final MemoryRepository memoryRepository;
    private final MemoryRiskAnalyzer memoryRiskAnalyzer;
    private final SecurityLogService securityLogService;
    private final PolicyEngine policyEngine;

    public MemoryService(
            MemoryRepository memoryRepository,
            MemoryRiskAnalyzer memoryRiskAnalyzer,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine) {

        this.memoryRepository = memoryRepository;
        this.memoryRiskAnalyzer = memoryRiskAnalyzer;
        this.securityLogService = securityLogService;
        this.policyEngine = policyEngine;
    }

    // ============================================================
    // GET ALL MEMORIES
    // ============================================================

    public List<Memory> getAllMemories() {

        List<Memory> memories = memoryRepository.findAll();

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
        // 2. ANALYZE SECURITY RISK
        // ========================================================

        analyzeRisk(memory);


        // ========================================================
        // 3. ASK POLICY ENGINE FOR DECISION
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

            SecurityLog log = new SecurityLog();

            // Blocked memory is NOT stored,
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

            // IMPORTANT:
            // Blocked memory never reaches persistent storage.

            return memory;
        }


        // ========================================================
        // 5. REVIEW MEDIUM-RISK MEMORY
        // ========================================================

        if (decision == PolicyDecision.REVIEW) {

            memory.setStatus("REVIEW");

            Memory savedMemory =
                    memoryRepository.save(memory);

            return savedMemory;
        }


        // ========================================================
        // 6. ALLOW LOW-RISK MEMORY
        // ========================================================

        memory.setStatus("SAFE");

        Memory savedMemory =
                memoryRepository.save(memory);

        return savedMemory;
    }

    // ============================================================
    // RISK ANALYSIS
    // ============================================================

    private void analyzeRisk(Memory memory) {

        MemoryRiskAnalyzer.RiskResult result =
                memoryRiskAnalyzer.analyze(
                        memory.getContent()
                );

        // Risk level
        memory.setRiskLevel(
                result.getRiskLevel()
        );

        // Risk score
        memory.setRiskScore(
                result.getRiskScore()
        );

        // Threat category
        memory.setRiskCategory(
                result.getCategory()
        );

        // Explanation
        memory.setRiskReason(
                result.getReason()
        );

        // ========================================================
        // KEEP STATUS SYNCHRONIZED WITH RISK
        // ========================================================

        if (result.getRiskScore() >= 80) {

            memory.setStatus("BLOCKED");

        } else if (result.getRiskScore() >= 50) {

            memory.setStatus("REVIEW");

        } else {

            memory.setStatus("SAFE");
        }
    }
}
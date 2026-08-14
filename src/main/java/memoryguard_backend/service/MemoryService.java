package memoryguard_backend.service;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.SecurityLog;

import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.security.HashUtil;
import memoryguard_backend.security.MemoryRiskAnalyzer;

import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class MemoryService {

    private final MemoryRepository memoryRepository;
    private final MemoryRiskAnalyzer memoryRiskAnalyzer;
    private final SecurityLogService securityLogService;

    public MemoryService(
            MemoryRepository memoryRepository,
            MemoryRiskAnalyzer memoryRiskAnalyzer,
            SecurityLogService securityLogService) {

        this.memoryRepository = memoryRepository;
        this.memoryRiskAnalyzer = memoryRiskAnalyzer;
        this.securityLogService = securityLogService;
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

        // Generate integrity hash before storing
        String hash =
                HashUtil.generateHash(
                        memory.getContent()
                );

        memory.setIntegrityHash(hash);

        // Save first so that memory receives an ID
        Memory savedMemory =
                memoryRepository.save(memory);

        // Analyze security risk
        analyzeRisk(savedMemory);

        // ========================================================
        // SECURITY DECISION
        // ========================================================

        if (savedMemory.getRiskScore() >= 80) {

            // HIGH RISK
            savedMemory.setStatus("BLOCKED");

            SecurityLog log = new SecurityLog();

            log.setMemoryId(
                    savedMemory.getId()
            );

            log.setRiskScore(
                    savedMemory.getRiskScore()
            );

            log.setThreatType(
                    savedMemory.getRiskCategory()
            );

            log.setActionTaken("BLOCKED");

            securityLogService.save(log);

        } else if (savedMemory.getRiskScore() >= 50) {

            // MEDIUM RISK
            savedMemory.setStatus("REVIEW");

        } else {

            // LOW RISK
            savedMemory.setStatus("SAFE");
        }

        return memoryRepository.save(savedMemory);
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
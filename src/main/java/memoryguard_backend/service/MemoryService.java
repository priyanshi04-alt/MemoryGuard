package memoryguard_backend.service;

import memoryguard_backend.entity.Memory;
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

    public MemoryService(
            MemoryRepository memoryRepository,
            MemoryRiskAnalyzer memoryRiskAnalyzer) {

        this.memoryRepository = memoryRepository;
        this.memoryRiskAnalyzer = memoryRiskAnalyzer;
    }

    public List<Memory> getAllMemories() {

        List<Memory> memories = memoryRepository.findAll();

        for (Memory memory : memories) {
            analyzeRisk(memory);
        }

        return memories;
    }

    public Optional<Memory> getMemoryById(Long id) {

        Optional<Memory> memory = memoryRepository.findById(id);

        if (memory.isPresent()) {
            analyzeRisk(memory.get());
        }

        return memory;
    }

    public boolean verifyIntegrity(Memory memory) {

        String calculatedHash =
                HashUtil.generateHash(memory.getContent());

        return calculatedHash.equals(memory.getIntegrityHash());
    }

    public Memory createMemory(Memory memory) {

        String hash =
                HashUtil.generateHash(memory.getContent());

        memory.setIntegrityHash(hash);

        Memory savedMemory =
                memoryRepository.save(memory);

        analyzeRisk(savedMemory);

        return savedMemory;
    }

    private void analyzeRisk(Memory memory) {

        MemoryRiskAnalyzer.RiskResult result =
                memoryRiskAnalyzer.analyze(memory.getContent());

        memory.setRiskLevel(result.getRiskLevel());
        memory.setRiskScore(result.getRiskScore());
        memory.setRiskCategory(result.getCategory());
        memory.setRiskReason(result.getReason());
    }
}
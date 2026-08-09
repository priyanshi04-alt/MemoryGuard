package memoryguard_backend.service;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.security.HashUtil;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MemoryService {

    private final MemoryRepository memoryRepository;

    public MemoryService(MemoryRepository memoryRepository) {
        this.memoryRepository = memoryRepository;
    }

    public List<Memory> getAllMemories() {
        return memoryRepository.findAll();
    }

    public java.util.Optional<Memory> getMemoryById(Long id) {
        return memoryRepository.findById(id);
    }

    public boolean verifyIntegrity(Memory memory) {
        String calculatedHash = HashUtil.generateHash(memory.getContent());
        return calculatedHash.equals(memory.getIntegrityHash());
    }

    public Memory createMemory(Memory memory) {

        String hash = HashUtil.generateHash(memory.getContent());

        memory.setIntegrityHash(hash);

        return memoryRepository.save(memory);
    }
}
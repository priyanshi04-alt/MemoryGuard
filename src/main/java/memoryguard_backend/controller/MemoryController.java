package memoryguard_backend.controller;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.repository.MemoryRepository;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/memories")
public class MemoryController {

    private final MemoryRepository memoryRepository;

    public MemoryController(MemoryRepository memoryRepository) {
        this.memoryRepository = memoryRepository;
    }

    @GetMapping
    public List<Memory> getAllMemories() {
        return memoryRepository.findAll();
    }

    @PostMapping
    public Memory createMemory(@RequestBody Memory memory) {
        return memoryRepository.save(memory);
    }
}
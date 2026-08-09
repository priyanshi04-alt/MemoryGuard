package memoryguard_backend.controller;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.service.MemoryService;

import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/memories")
public class MemoryController {

    private final MemoryService memoryService;

    public MemoryController(MemoryService memoryService) {
        this.memoryService = memoryService;
    }

    @GetMapping
    public List<Memory> getAllMemories() {
        return memoryService.getAllMemories();
    }

    @PostMapping
    public Memory createMemory(@RequestBody Memory memory) {
        return memoryService.createMemory(memory);
    }

    @GetMapping("/{id}/verify")
    public org.springframework.http.ResponseEntity<VerificationResult> verifyMemory(@PathVariable Long id) {
        return memoryService.getMemoryById(id)
            .map(memory -> {
                boolean isIntact = memoryService.verifyIntegrity(memory);
                String status = isIntact ? "INTACT" : "TAMPERED";
                String message = isIntact ? "Memory integrity verified successfully" : "Memory integrity verification failed";
                return org.springframework.http.ResponseEntity.ok(new VerificationResult(id, status, message));
            })
            .orElseGet(() -> org.springframework.http.ResponseEntity.notFound().build());
    }

    public record VerificationResult(Long memoryId, String status, String message) {}
}
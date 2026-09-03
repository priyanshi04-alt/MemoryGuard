package memoryguard_backend.controller;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.service.MemoryService;

import memoryguard_backend.security.content.ContentAnalysisResult;
import memoryguard_backend.security.signals.SecuritySignals;
import org.springframework.http.ResponseEntity;
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
    public List<Memory> getAllMemories(@RequestParam(value = "status", defaultValue = "SAFE") String status) {
        return memoryService.getMemoriesByStatus(status);
    }

    @PostMapping
    public Memory createMemory(@RequestBody Memory memory) {
        return memoryService.createMemory(memory);
    }

    @GetMapping("/{id}/verify")
    public ResponseEntity<VerificationResult> verifyMemory(@PathVariable Long id) {
        return memoryService.getMemoryById(id)
            .map(memory -> {
                boolean isIntact = memoryService.verifyIntegrity(memory);
                String status = isIntact ? "INTACT" : "TAMPERED";
                String message = isIntact ? "Memory integrity verified successfully" : "Memory integrity verification failed";
                return ResponseEntity.ok(new VerificationResult(id, status, message));
            })
            .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/security-signals")
    public ResponseEntity<SecuritySignals> getSecuritySignals(@PathVariable Long id) {
        return memoryService.extractSecuritySignals(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/security-signals")
    public ResponseEntity<SecuritySignals> extractSecuritySignals(@RequestBody Memory memory) {
        SecuritySignals signals = memoryService.extractSecuritySignals(memory);
        return ResponseEntity.ok(signals);
    }

    @PostMapping("/analyze-content")
    public ResponseEntity<ContentAnalysisResult> analyzeContent(@RequestBody Memory memory) {
        ContentAnalysisResult result = memoryService.analyzeContent(memory);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/{id}/content-signals")
    public ResponseEntity<ContentAnalysisResult> getContentSignals(@PathVariable Long id) {
        return memoryService.getMemoryById(id)
                .map(memory -> ResponseEntity.ok(memoryService.analyzeContent(memory.getContent())))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/stats")
    public MemoryStats getMemoryStats() {
        return memoryService.getMemoryStats();
    }

    public record VerificationResult(Long memoryId, String status, String message) {}
    
    public record MemoryStats(
        long totalTrusted,
        long blockedAttempts,
        long needsReview,
        RiskDistribution riskDistribution
    ) {}

    public record RiskDistribution(
        long low,
        long medium,
        long high
    ) {}
}
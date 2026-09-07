package memoryguard_backend.controller;

import memoryguard_backend.entity.DeniedMemoryRecord;
import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.QuarantinedMemory;
import memoryguard_backend.service.QuarantineManagementService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/quarantine")
public class QuarantineController {

    private final QuarantineManagementService quarantineManagementService;

    public QuarantineController(QuarantineManagementService quarantineManagementService) {
        this.quarantineManagementService = quarantineManagementService;
    }

    @GetMapping
    public List<QuarantinedMemory> getQuarantinedMemories(
            @RequestParam(value = "status", defaultValue = "PENDING") String status) {
        return quarantineManagementService.listQuarantinedMemories(status);
    }

    @GetMapping("/{id}")
    public ResponseEntity<QuarantinedMemory> getQuarantinedMemoryById(@PathVariable Long id) {
        return quarantineManagementService.getQuarantinedMemoryById(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/denied")
    public List<DeniedMemoryRecord> getDeniedRecords() {
        return quarantineManagementService.listDeniedRecords();
    }

    @PostMapping("/{id}/approve")
    public ResponseEntity<?> approveQuarantine(
            @PathVariable Long id,
            @RequestHeader(value = "X-Operator-Id", required = false) String headerOperatorId,
            @RequestBody(required = false) ResolutionRequest request) {

        String operatorId = extractOperatorId(headerOperatorId, request);
        String reason = request != null ? request.reason() : "Explicit operator approval via REST API";

        try {
            Memory activeMemory = quarantineManagementService.approveQuarantinedMemory(id, operatorId, reason);
            return ResponseEntity.ok(activeMemory);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse("INVALID_STATE", e.getMessage()));
        }
    }

    @PostMapping("/{id}/reject")
    public ResponseEntity<?> rejectQuarantine(
            @PathVariable Long id,
            @RequestHeader(value = "X-Operator-Id", required = false) String headerOperatorId,
            @RequestBody(required = false) ResolutionRequest request) {

        String operatorId = extractOperatorId(headerOperatorId, request);
        String reason = request != null ? request.reason() : "Explicit operator rejection via REST API";

        try {
            DeniedMemoryRecord deniedRecord = quarantineManagementService.rejectQuarantinedMemory(id, operatorId, reason);
            return ResponseEntity.ok(deniedRecord);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        } catch (SecurityException e) {
            return ResponseEntity.status(403).body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse("INVALID_STATE", e.getMessage()));
        }
    }

    private String extractOperatorId(String headerOperatorId, ResolutionRequest request) {
        if (headerOperatorId != null && !headerOperatorId.trim().isEmpty()) {
            return headerOperatorId.trim();
        }
        if (request != null && request.operatorId() != null && !request.operatorId().trim().isEmpty()) {
            return request.operatorId().trim();
        }
        return null;
    }

    public record ResolutionRequest(String operatorId, String reason) {}
    public record ErrorResponse(String errorCode, String message) {}
}

package memoryguard_backend.controller;

import memoryguard_backend.dto.AuditIntegrityResult;
import memoryguard_backend.dto.MemoryInvestigationReport;
import memoryguard_backend.entity.SecurityAuditEvent;
import memoryguard_backend.service.SecurityAuditService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private final SecurityAuditService auditService;

    public AuditController(SecurityAuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping
    public ResponseEntity<?> getAllAuditEvents(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {
        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        List<SecurityAuditEvent> events = auditService.getAllEvents();
        return ResponseEntity.ok(events);
    }

    @GetMapping("/integrity")
    public ResponseEntity<?> verifyAuditIntegrity(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {
        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        AuditIntegrityResult result = auditService.verifyAuditIntegrity();
        return ResponseEntity.ok(result);
    }

    @GetMapping("/correlation/{correlationId}")
    public ResponseEntity<?> getEventsByCorrelationId(
            @PathVariable String correlationId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {
        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        List<SecurityAuditEvent> events = auditService.getEventsByCorrelationId(correlationId);
        return ResponseEntity.ok(events);
    }

    @GetMapping("/investigation/{correlationId}")
    public ResponseEntity<?> getInvestigationReport(
            @PathVariable String correlationId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {
        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            MemoryInvestigationReport report = auditService.investigateCorrelation(correlationId);
            return ResponseEntity.ok(report);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(new ErrorResponse("BAD_REQUEST", e.getMessage()));
        }
    }

    @GetMapping("/memory/{memoryId}")
    public ResponseEntity<?> getEventsByMemoryId(
            @PathVariable Long memoryId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {
        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        List<SecurityAuditEvent> events = auditService.getEventsByMemoryId(memoryId);
        return ResponseEntity.ok(events);
    }

    @GetMapping("/memory/{memoryId}/timeline")
    public ResponseEntity<?> getTimelineByMemoryId(
            @PathVariable Long memoryId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {
        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        List<SecurityAuditEvent> timeline = auditService.getTimelineByMemoryId(memoryId);
        return ResponseEntity.ok(timeline);
    }

    @GetMapping("/{idOrEventId}")
    public ResponseEntity<?> getAuditEventById(
            @PathVariable String idOrEventId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {
        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        // Try numeric ID first
        try {
            Long numericId = Long.parseLong(idOrEventId);
            Optional<SecurityAuditEvent> eventOpt = auditService.getEventById(numericId);
            if (eventOpt.isPresent()) {
                return ResponseEntity.ok(eventOpt.get());
            }
        } catch (NumberFormatException ignored) {
        }

        // Try eventId string UUID
        Optional<SecurityAuditEvent> eventOpt = auditService.getEventByEventId(idOrEventId);
        return eventOpt.map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private ResponseEntity<?> validateOperatorAuthorization(String operatorId) {
        if (operatorId == null || operatorId.trim().isEmpty() || "ANONYMOUS".equalsIgnoreCase(operatorId.trim())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", "Authorization required: valid operator identity (X-Operator-Id) must be provided to access security audit endpoints."));
        }
        return null;
    }

    public record ErrorResponse(String errorCode, String message) {}
}

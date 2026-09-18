package memoryguard_backend.controller;

import memoryguard_backend.dto.GovernanceAnomalySummaryResponse;
import memoryguard_backend.dto.GovernanceFindingResponse;
import memoryguard_backend.entity.GovernanceSecurityFinding;
import memoryguard_backend.service.GovernanceAnomalyDetectionService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/security/policy/anomalies")
public class GovernanceAnomalyController {

    private final GovernanceAnomalyDetectionService anomalyService;

    @Autowired
    public GovernanceAnomalyController(GovernanceAnomalyDetectionService anomalyService) {
        this.anomalyService = anomalyService;
    }

    @GetMapping
    public ResponseEntity<?> getAllFindings(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            List<GovernanceSecurityFinding> findings = anomalyService.getAllFindings(operatorId);
            List<GovernanceFindingResponse> responseList = findings.stream()
                    .map(GovernanceFindingResponse::fromEntity)
                    .collect(Collectors.toList());
            return ResponseEntity.ok(responseList);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/open")
    public ResponseEntity<?> getOpenFindings(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            List<GovernanceSecurityFinding> openFindings = anomalyService.getOpenFindings(operatorId);
            List<GovernanceFindingResponse> responseList = openFindings.stream()
                    .map(GovernanceFindingResponse::fromEntity)
                    .collect(Collectors.toList());
            return ResponseEntity.ok(responseList);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/summary")
    public ResponseEntity<?> getAnomalySummary(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            GovernanceAnomalySummaryResponse summary = anomalyService.getAnomalySummary(operatorId);
            return ResponseEntity.ok(summary);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getFindingById(
            @PathVariable String id,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            GovernanceSecurityFinding finding = anomalyService.getFindingById(id, operatorId);
            return ResponseEntity.ok(GovernanceFindingResponse.fromEntity(finding));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("NOT_FOUND", e.getMessage()));
        }
    }

    @PostMapping("/{id}/acknowledge")
    public ResponseEntity<?> acknowledgeFinding(
            @PathVariable String id,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @RequestBody(required = false) Map<String, Object> body) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        String notes = null;
        if (body != null) {
            if (body.containsKey("notes") && body.get("notes") != null) {
                notes = body.get("notes").toString();
            } else if (body.containsKey("resolutionNotes") && body.get("resolutionNotes") != null) {
                notes = body.get("resolutionNotes").toString();
            }
        }

        try {
            GovernanceSecurityFinding acknowledged = anomalyService.acknowledgeFinding(id, operatorId, notes);
            return ResponseEntity.ok(GovernanceFindingResponse.fromEntity(acknowledged));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("NOT_FOUND", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("INVALID_STATE", e.getMessage()));
        }
    }

    @PostMapping("/{id}/resolve")
    public ResponseEntity<?> resolveFinding(
            @PathVariable String id,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @RequestBody(required = false) Map<String, Object> body) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        String notes = null;
        if (body != null) {
            if (body.containsKey("notes") && body.get("notes") != null) {
                notes = body.get("notes").toString();
            } else if (body.containsKey("resolutionNotes") && body.get("resolutionNotes") != null) {
                notes = body.get("resolutionNotes").toString();
            }
        }

        try {
            GovernanceSecurityFinding resolved = anomalyService.resolveFinding(id, operatorId, notes);
            return ResponseEntity.ok(GovernanceFindingResponse.fromEntity(resolved));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("NOT_FOUND", e.getMessage()));
        } catch (IllegalStateException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("INVALID_STATE", e.getMessage()));
        }
    }

    private ResponseEntity<?> validateOperatorAuthorization(String operatorId) {
        if (operatorId == null || operatorId.trim().isEmpty() || "ANONYMOUS".equalsIgnoreCase(operatorId.trim())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", "Authorization required: valid operator identity (X-Operator-Id) must be provided."));
        }
        return null;
    }

    public record ErrorResponse(String errorCode, String message) {}
}

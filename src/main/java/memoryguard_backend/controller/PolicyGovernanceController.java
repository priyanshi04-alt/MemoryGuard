package memoryguard_backend.controller;

import memoryguard_backend.dto.*;
import memoryguard_backend.entity.PolicyChangeProposal;
import memoryguard_backend.entity.PolicyVersion;
import memoryguard_backend.service.PolicyGovernanceObservabilityService;
import memoryguard_backend.service.PolicyGovernanceService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/security/policy")
public class PolicyGovernanceController {

    private final PolicyGovernanceService governanceService;
    private final PolicyGovernanceObservabilityService observabilityService;

    @Autowired
    public PolicyGovernanceController(
            PolicyGovernanceService governanceService,
            @Autowired(required = false) PolicyGovernanceObservabilityService observabilityService) {
        this.governanceService = governanceService;
        this.observabilityService = observabilityService;
    }

    public PolicyGovernanceController(PolicyGovernanceService governanceService) {
        this(governanceService, null);
    }

    @PostMapping("/proposals")
    public ResponseEntity<?> createProposal(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @RequestBody(required = false) CreatePolicyProposalRequest request) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            PolicyChangeProposal proposal = governanceService.createProposal(request, operatorId);
            return ResponseEntity.status(HttpStatus.CREATED).body(proposal);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse("BAD_REQUEST", e.getMessage()));
        }
    }

    @GetMapping("/proposals")
    public ResponseEntity<?> getAllProposals(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            List<PolicyChangeProposal> proposals = governanceService.getAllProposals(operatorId);
            return ResponseEntity.ok(proposals);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/proposals/{proposalId}")
    public ResponseEntity<?> getProposalById(
            @PathVariable String proposalId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            PolicyChangeProposal proposal = governanceService.getProposalById(proposalId, operatorId);
            return ResponseEntity.ok(proposal);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorResponse("NOT_FOUND", e.getMessage()));
        }
    }

    @PostMapping("/proposals/{proposalId}/approve")
    public ResponseEntity<?> approveProposal(
            @PathVariable String proposalId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @RequestBody(required = false) GovernanceActionRequest request) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        String reason = request != null ? request.reason() : null;

        try {
            PolicyChangeProposal approved = governanceService.approveProposal(proposalId, operatorId, reason);
            return ResponseEntity.ok(approved);
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

    @PostMapping("/proposals/{proposalId}/reject")
    public ResponseEntity<?> rejectProposal(
            @PathVariable String proposalId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @RequestBody(required = false) Map<String, Object> body) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        String reason = null;
        if (body != null) {
            if (body.containsKey("rejectionReason") && body.get("rejectionReason") != null) {
                reason = body.get("rejectionReason").toString();
            } else if (body.containsKey("reason") && body.get("reason") != null) {
                reason = body.get("reason").toString();
            }
        }

        try {
            PolicyChangeProposal rejected = governanceService.rejectProposal(proposalId, operatorId, reason);
            return ResponseEntity.ok(rejected);
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

    @PostMapping("/proposals/{proposalId}/activate")
    public ResponseEntity<?> activateProposal(
            @PathVariable String proposalId,
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId,
            @RequestBody(required = false) GovernanceActionRequest request) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        String reason = request != null ? request.reason() : null;

        try {
            PolicyVersion activeVersion = governanceService.activateProposal(proposalId, operatorId, reason);
            return ResponseEntity.ok(activeVersion);
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

    @GetMapping("/active")
    public ResponseEntity<?> getActivePolicy(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            PolicyVersion activePolicy = governanceService.getActivePolicy(operatorId);
            return ResponseEntity.ok(activePolicy);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/history")
    public ResponseEntity<?> getPolicyHistory(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            List<PolicyVersion> history = governanceService.getPolicyHistory(operatorId);
            return ResponseEntity.ok(history);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    // ====================================================================
    // DAY 26 GOVERNANCE OBSERVABILITY & METRICS ENDPOINTS (READ-ONLY)
    // ====================================================================

    @GetMapping("/metrics")
    public ResponseEntity<?> getGovernanceMetrics(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            if (observabilityService == null) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .body(new ErrorResponse("SERVICE_UNAVAILABLE", "Observability service unavailable"));
            }
            GovernanceMetricsResponse metrics = observabilityService.getGovernanceMetrics(operatorId);
            return ResponseEntity.ok(metrics);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/analytics")
    public ResponseEntity<?> getPolicyAnalytics(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            if (observabilityService == null) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .body(new ErrorResponse("SERVICE_UNAVAILABLE", "Observability service unavailable"));
            }
            PolicyAnalyticsResponse analytics = observabilityService.getPolicyAnalytics(operatorId);
            return ResponseEntity.ok(analytics);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/operators")
    public ResponseEntity<?> getOperatorActivitySummary(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            if (observabilityService == null) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .body(new ErrorResponse("SERVICE_UNAVAILABLE", "Observability service unavailable"));
            }
            List<OperatorGovernanceActivityResponse> summaries = observabilityService.getOperatorActivitySummary(operatorId);
            return ResponseEntity.ok(summaries);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    @GetMapping("/health")
    public ResponseEntity<?> getGovernanceSecurityHealth(
            @RequestHeader(value = "X-Operator-Id", required = false) String operatorId) {

        ResponseEntity<?> authCheck = validateOperatorAuthorization(operatorId);
        if (authCheck != null) return authCheck;

        try {
            if (observabilityService == null) {
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                        .body(new ErrorResponse("SERVICE_UNAVAILABLE", "Observability service unavailable"));
            }
            GovernanceHealthResponse health = observabilityService.getGovernanceSecurityHealth(operatorId);
            return ResponseEntity.ok(health);
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", e.getMessage()));
        }
    }

    private ResponseEntity<?> validateOperatorAuthorization(String operatorId) {
        if (operatorId == null || operatorId.trim().isEmpty() || "ANONYMOUS".equalsIgnoreCase(operatorId.trim())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new ErrorResponse("FORBIDDEN", "Authorization required: valid operator identity (X-Operator-Id) must be provided."));
        }
        return null;
    }

    public record GovernanceActionRequest(String reason) {}
    public record ErrorResponse(String errorCode, String message) {}
}

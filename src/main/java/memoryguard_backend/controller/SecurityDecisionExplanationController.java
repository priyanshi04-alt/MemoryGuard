package memoryguard_backend.controller;

import memoryguard_backend.security.explainability.SecurityDecisionExplanation;
import memoryguard_backend.security.explainability.SecurityDecisionExplanationService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * REST Control Plane for Security Decision Explainability & Threat Intelligence.
 * Exposes read-only endpoints to inspect decision rationale, evidence chains,
 * threat categories, and contributing factors without altering decisions or leaking plaintext.
 */
@RestController
@RequestMapping("/api/security/decisions")
public class SecurityDecisionExplanationController {

    private final SecurityDecisionExplanationService explanationService;

    public SecurityDecisionExplanationController(SecurityDecisionExplanationService explanationService) {
        this.explanationService = explanationService;
    }

    /**
     * GET /api/security/decisions/{memoryId}
     * Retrieves security decision explanation for a specific memory ID.
     */
    @GetMapping("/{memoryId}")
    public ResponseEntity<SecurityDecisionExplanation> getExplanationByMemoryId(@PathVariable Long memoryId) {
        return explanationService.getExplanationByMemoryId(memoryId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /**
     * GET /api/security/decisions/correlation/{correlationId}
     * Retrieves security decision explanation for a specific correlation ID.
     */
    @GetMapping("/correlation/{correlationId}")
    public ResponseEntity<SecurityDecisionExplanation> getExplanationByCorrelationId(@PathVariable String correlationId) {
        return explanationService.getExplanationByCorrelationId(correlationId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}

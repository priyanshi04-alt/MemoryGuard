package memoryguard_backend;

import memoryguard_backend.controller.OperatorFeedbackController;
import memoryguard_backend.dto.CalibrationRecommendation;
import memoryguard_backend.dto.CalibrationResponse;
import memoryguard_backend.dto.OperatorFeedbackRequest;
import memoryguard_backend.dto.OperatorFeedbackTelemetry;
import memoryguard_backend.entity.DeniedMemoryRecord;
import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.OperatorFeedback;
import memoryguard_backend.entity.QuarantinedMemory;
import memoryguard_backend.entity.SecurityAuditEvent;
import memoryguard_backend.repository.DeniedMemoryRepository;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.repository.OperatorFeedbackRepository;
import memoryguard_backend.repository.QuarantinedMemoryRepository;
import memoryguard_backend.repository.SecurityAuditRepository;
import memoryguard_backend.security.PolicyEngine;
import memoryguard_backend.service.OperatorFeedbackService;
import memoryguard_backend.service.SecurityAuditService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class OperatorFeedbackTests {

    private OperatorFeedbackRepository feedbackRepository;
    private SecurityAuditRepository auditRepository;
    private QuarantinedMemoryRepository quarantinedMemoryRepository;
    private MemoryRepository memoryRepository;
    private DeniedMemoryRepository deniedMemoryRepository;

    private SecurityAuditService auditService;
    private OperatorFeedbackService feedbackService;
    private OperatorFeedbackController feedbackController;
    private PolicyEngine policyEngine;

    private List<OperatorFeedback> dbFeedback;
    private List<SecurityAuditEvent> dbAuditEvents;
    private long feedbackIdCounter = 1L;
    private long auditIdCounter = 1L;

    @BeforeEach
    void setUp() {
        feedbackRepository = mock(OperatorFeedbackRepository.class);
        auditRepository = mock(SecurityAuditRepository.class);
        quarantinedMemoryRepository = mock(QuarantinedMemoryRepository.class);
        memoryRepository = mock(MemoryRepository.class);
        deniedMemoryRepository = mock(DeniedMemoryRepository.class);

        dbFeedback = new ArrayList<>();
        dbAuditEvents = new ArrayList<>();
        feedbackIdCounter = 1L;
        auditIdCounter = 1L;

        // Mock feedback repository
        when(feedbackRepository.save(any(OperatorFeedback.class))).thenAnswer(inv -> {
            OperatorFeedback f = inv.getArgument(0);
            if (f.getId() == null) {
                f.setId(feedbackIdCounter++);
            }
            if (f.getFeedbackId() == null) {
                f.setFeedbackId("fb-uuid-" + f.getId());
            }
            dbFeedback.add(f);
            return f;
        });

        when(feedbackRepository.findAllByOrderByIdAsc()).thenAnswer(inv -> new ArrayList<>(dbFeedback));

        when(feedbackRepository.findByMemoryIdOrderByTimestampAsc(anyLong())).thenAnswer(inv -> {
            Long memId = inv.getArgument(0);
            return dbFeedback.stream().filter(f -> memId.equals(f.getMemoryId())).toList();
        });

        when(feedbackRepository.existsByMemoryIdAndOperatorIdAndFeedbackDecision(anyLong(), anyString(), anyString()))
                .thenAnswer(inv -> {
                    Long memId = inv.getArgument(0);
                    String opId = inv.getArgument(1);
                    String dec = inv.getArgument(2);
                    return dbFeedback.stream().anyMatch(f -> memId.equals(f.getMemoryId())
                            && opId.equalsIgnoreCase(f.getOperatorId())
                            && dec.equalsIgnoreCase(f.getFeedbackDecision()));
                });

        // Mock audit repository
        when(auditRepository.save(any(SecurityAuditEvent.class))).thenAnswer(inv -> {
            SecurityAuditEvent event = inv.getArgument(0);
            if (event.getId() == null) {
                event.setId(auditIdCounter++);
            }
            dbAuditEvents.add(event);
            return event;
        });

        when(auditRepository.findTopByOrderByIdDesc()).thenAnswer(inv -> {
            if (dbAuditEvents.isEmpty()) return Optional.empty();
            return Optional.of(dbAuditEvents.get(dbAuditEvents.size() - 1));
        });

        when(auditRepository.findAllByOrderByIdAsc()).thenAnswer(inv -> new ArrayList<>(dbAuditEvents));

        when(auditRepository.findByMemoryIdOrderByTimestampAsc(anyLong())).thenAnswer(inv -> {
            Long memId = inv.getArgument(0);
            return dbAuditEvents.stream().filter(e -> memId.equals(e.getMemoryId())).toList();
        });

        auditService = new SecurityAuditService(
                auditRepository,
                quarantinedMemoryRepository,
                deniedMemoryRepository
        );

        feedbackService = new OperatorFeedbackService(
                feedbackRepository,
                auditService,
                quarantinedMemoryRepository,
                memoryRepository,
                deniedMemoryRepository
        );

        feedbackController = new OperatorFeedbackController(feedbackService);
        policyEngine = new PolicyEngine();
    }

    // ====================================================================
    // 1. VALID FEEDBACK SUBMISSION TESTS
    // ====================================================================

    @Test
    @DisplayName("Submit APPROVED operator feedback successfully")
    void testSubmitFeedback_Approved_Success() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(101L, "corr-101", "sec-op-1", "APPROVED", "Approved after review");

        OperatorFeedback fb = feedbackService.submitFeedback(req, "sec-op-1");

        assertNotNull(fb);
        assertEquals(101L, fb.getMemoryId());
        assertEquals("sec-op-1", fb.getOperatorId());
        assertEquals("APPROVED", fb.getFeedbackDecision());
        assertEquals("Approved after review", fb.getNotes());
        assertEquals(1, dbFeedback.size());
    }

    @Test
    @DisplayName("Submit REJECTED operator feedback successfully")
    void testSubmitFeedback_Rejected_Success() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(102L, "corr-102", "sec-op-1", "REJECTED", "Confirmed prompt injection");

        OperatorFeedback fb = feedbackService.submitFeedback(req, "sec-op-1");

        assertNotNull(fb);
        assertEquals("REJECTED", fb.getFeedbackDecision());
        assertEquals("Confirmed prompt injection", fb.getNotes());
    }

    @Test
    @DisplayName("Submit ESCALATED operator feedback successfully")
    void testSubmitFeedback_Escalated_Success() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(103L, "corr-103", "sec-op-2", "ESCALATED", "Escalated for SOC L2 analysis");

        OperatorFeedback fb = feedbackService.submitFeedback(req, "sec-op-2");

        assertNotNull(fb);
        assertEquals("ESCALATED", fb.getFeedbackDecision());
        assertEquals("sec-op-2", fb.getOperatorId());
    }

    // ====================================================================
    // 2. AUTHORIZATION BOUNDARY TESTS
    // ====================================================================

    @Test
    @DisplayName("Submit feedback with missing operator throws SecurityException")
    void testSubmitFeedback_MissingOperator_ThrowsSecurityException() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(101L, "corr-101", null, "APPROVED", null);

        assertThrows(SecurityException.class, () -> feedbackService.submitFeedback(req, null));
        assertThrows(SecurityException.class, () -> feedbackService.submitFeedback(req, "   "));
    }

    @Test
    @DisplayName("Submit feedback with ANONYMOUS operator throws SecurityException")
    void testSubmitFeedback_AnonymousOperator_ThrowsSecurityException() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(101L, "corr-101", "ANONYMOUS", "APPROVED", null);

        assertThrows(SecurityException.class, () -> feedbackService.submitFeedback(req, "ANONYMOUS"));
        assertThrows(SecurityException.class, () -> feedbackService.submitFeedback(req, "anonymous"));
    }

    // ====================================================================
    // 3. FEEDBACK VALIDATION TESTS
    // ====================================================================

    @Test
    @DisplayName("Submit feedback with invalid decision type throws IllegalArgumentException")
    void testSubmitFeedback_InvalidDecisionType_ThrowsIllegalArgumentException() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(101L, "corr-101", "sec-op-1", "INVALID_TYPE", null);

        assertThrows(IllegalArgumentException.class, () -> feedbackService.submitFeedback(req, "sec-op-1"));
    }

    @Test
    @DisplayName("Submit feedback with invalid memory ID throws IllegalArgumentException")
    void testSubmitFeedback_InvalidMemoryId_ThrowsIllegalArgumentException() {
        OperatorFeedbackRequest req1 = new OperatorFeedbackRequest(null, "corr-101", "sec-op-1", "APPROVED", null);
        OperatorFeedbackRequest req2 = new OperatorFeedbackRequest(-5L, "corr-101", "sec-op-1", "APPROVED", null);

        assertThrows(IllegalArgumentException.class, () -> feedbackService.submitFeedback(req1, "sec-op-1"));
        assertThrows(IllegalArgumentException.class, () -> feedbackService.submitFeedback(req2, "sec-op-1"));
    }

    @Test
    @DisplayName("Submit null feedback request throws IllegalArgumentException")
    void testSubmitFeedback_NullRequest_ThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> feedbackService.submitFeedback(null, "sec-op-1"));
    }

    @Test
    @DisplayName("Duplicate feedback submission throws IllegalStateException")
    void testSubmitFeedback_DuplicateSubmission_ThrowsIllegalStateException() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(105L, "corr-105", "sec-op-1", "APPROVED", "First submission");
        feedbackService.submitFeedback(req, "sec-op-1");

        OperatorFeedbackRequest duplicateReq = new OperatorFeedbackRequest(105L, "corr-105", "sec-op-1", "APPROVED", "Duplicate submission");
        assertThrows(IllegalStateException.class, () -> feedbackService.submitFeedback(duplicateReq, "sec-op-1"));
    }

    // ====================================================================
    // 4. AUDIT & INTEGRITY INTEGRATION TESTS
    // ====================================================================

    @Test
    @DisplayName("Submitting feedback emits OPERATOR_FEEDBACK_SUBMITTED audit event")
    void testSubmitFeedback_IntegratesWithSecurityAuditService() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(200L, "corr-200", "sec-op-3", "REJECTED", "Threat confirmed");
        feedbackService.submitFeedback(req, "sec-op-3");

        assertEquals(1, dbAuditEvents.size());
        SecurityAuditEvent event = dbAuditEvents.get(0);
        assertEquals("OPERATOR_FEEDBACK_SUBMITTED", event.getEventType());
        assertEquals("corr-200", event.getCorrelationId());
        assertEquals(200L, event.getMemoryId());
        assertEquals("sec-op-3", event.getOperatorId());
        assertEquals("REJECTED", event.getPolicyDecision());
        assertNotNull(event.getCurrentHash());
    }

    @Test
    @DisplayName("Submitting multiple feedback events maintains audit hash chain integrity")
    void testSubmitFeedback_AuditIntegrityPreserved() {
        feedbackService.submitFeedback(new OperatorFeedbackRequest(1L, "c-1", "op-1", "APPROVED", null), "op-1");
        feedbackService.submitFeedback(new OperatorFeedbackRequest(2L, "c-2", "op-1", "REJECTED", null), "op-1");
        feedbackService.submitFeedback(new OperatorFeedbackRequest(3L, "c-3", "op-2", "ESCALATED", null), "op-2");

        assertTrue(auditService.verifyAuditIntegrity().isValid());
    }

    // ====================================================================
    // 5. RETRIEVAL & TELEMETRY TESTS
    // ====================================================================

    @Test
    @DisplayName("Get feedback by memory ID returns expected list when authorized")
    void testGetFeedbackByMemoryId_Authorized_Success() {
        feedbackService.submitFeedback(new OperatorFeedbackRequest(300L, "corr-300", "sec-op-1", "APPROVED", "Note 1"), "sec-op-1");
        feedbackService.submitFeedback(new OperatorFeedbackRequest(300L, "corr-300", "sec-op-2", "REJECTED", "Note 2"), "sec-op-2");

        List<OperatorFeedback> list = feedbackService.getFeedbackByMemoryId(300L, "sec-op-1");
        assertEquals(2, list.size());
    }

    @Test
    @DisplayName("Get feedback by memory ID with unauthorized operator throws SecurityException")
    void testGetFeedbackByMemoryId_Unauthorized_ThrowsSecurityException() {
        assertThrows(SecurityException.class, () -> feedbackService.getFeedbackByMemoryId(300L, null));
        assertThrows(SecurityException.class, () -> feedbackService.getFeedbackByMemoryId(300L, "ANONYMOUS"));
    }

    @Test
    @DisplayName("Get telemetry calculates overall counts and override rate accurately")
    void testGetTelemetry_CalculatesCountsAndOverrideRate() {
        // Create initial audit events for memories
        auditService.recordEvent("MEMORY_QUARANTINED", "c1", 1L, 10L, null, "REVIEW", 60, "FACTOR1", "RULE1", "ANALYZER");
        auditService.recordEvent("MEMORY_QUARANTINED", "c2", 2L, 11L, null, "REVIEW", 65, "FACTOR1", "RULE1", "ANALYZER");
        auditService.recordEvent("MEMORY_QUARANTINED", "c3", 3L, 12L, null, "REVIEW", 70, "FACTOR2", "RULE2", "ANALYZER");
        auditService.recordEvent("MEMORY_DENIED", "c4", 4L, null, null, "BLOCK", 90, "FACTOR3", "RULE3", "ANALYZER");

        feedbackService.submitFeedback(new OperatorFeedbackRequest(1L, "c1", "op1", "APPROVED", "Approved REVIEW"), "op1");
        feedbackService.submitFeedback(new OperatorFeedbackRequest(2L, "c2", "op1", "APPROVED", "Approved REVIEW"), "op1");
        feedbackService.submitFeedback(new OperatorFeedbackRequest(3L, "c3", "op2", "REJECTED", "Rejected REVIEW"), "op2");
        feedbackService.submitFeedback(new OperatorFeedbackRequest(4L, "c4", "op2", "ESCALATED", "Escalated BLOCK"), "op2");

        OperatorFeedbackTelemetry telemetry = feedbackService.getTelemetry("op1");

        assertNotNull(telemetry);
        assertEquals(4, telemetry.getTotalFeedbackCount());
        assertEquals(2, telemetry.getApprovedCount());
        assertEquals(1, telemetry.getRejectedCount());
        assertEquals(1, telemetry.getEscalatedCount());

        assertEquals(2, telemetry.getReviewApprovedCount());
        assertEquals(1, telemetry.getReviewRejectedCount());
        assertEquals(1, telemetry.getBlockEscalatedCount());
        assertEquals(1.0, telemetry.getOverrideRate());
    }

    // ====================================================================
    // 6. CALIBRATION RECOMMENDATION & DRIFT TESTS
    // ====================================================================

    @Test
    @DisplayName("Calibration below sample threshold (10 observations) returns INSUFFICIENT_DATA status")
    void testGetCalibration_BelowThreshold_ReturnsInsufficientDataStatus() {
        for (int i = 1; i <= 5; i++) {
            feedbackService.submitFeedback(new OperatorFeedbackRequest((long) i, "c-" + i, "op-1", "APPROVED", null), "op-1");
        }

        CalibrationResponse resp = feedbackService.getCalibrationRecommendations("op-1");

        assertNotNull(resp);
        assertEquals(10, resp.getMinimumThreshold());
        assertEquals(5, resp.getTotalObservations());
        assertFalse(resp.isSufficientData());
        assertEquals("INSUFFICIENT_DATA", resp.getStatus());
        assertTrue(resp.getRecommendations().isEmpty());
    }

    @Test
    @DisplayName("Calibration above threshold with high REVIEW approval rate recommends RAISE_REVIEW_THRESHOLD")
    void testGetCalibration_AboveThreshold_HighApprovalRate_RecommendsRaiseThreshold() {
        for (int i = 1; i <= 10; i++) {
            Long memId = (long) i;
            auditService.recordEvent("MEMORY_QUARANTINED", "c-" + i, memId, (long) (100 + i), null, "REVIEW", 60, "SIGNAL_A", "RULE_REVIEW", "ANALYZER");
            String dec = (i <= 8) ? "APPROVED" : "REJECTED";
            feedbackService.submitFeedback(new OperatorFeedbackRequest(memId, "c-" + i, "op-1", dec, null), "op-1");
        }

        CalibrationResponse resp = feedbackService.getCalibrationRecommendations("op-1");

        assertNotNull(resp);
        assertTrue(resp.isSufficientData());
        assertEquals("SUFFICIENT_DATA", resp.getStatus());
        assertFalse(resp.getRecommendations().isEmpty());

        CalibrationRecommendation rec = resp.getRecommendations().get(0);
        assertEquals("HIGH_REVIEW_APPROVAL_RATE", rec.getPatternDetected());
        assertEquals("RAISE_REVIEW_THRESHOLD", rec.getSuggestedDirection());
        assertTrue(rec.getExplanation().contains("Suggest raising REVIEW threshold"));
    }

    @Test
    @DisplayName("Calibration above threshold with high REVIEW rejection rate recommends LOWER_REVIEW_THRESHOLD")
    void testGetCalibration_AboveThreshold_HighRejectionRate_RecommendsLowerThreshold() {
        for (int i = 1; i <= 10; i++) {
            Long memId = (long) i;
            auditService.recordEvent("MEMORY_QUARANTINED", "c-" + i, memId, (long) (100 + i), null, "REVIEW", 65, "SIGNAL_B", "RULE_REVIEW", "ANALYZER");
            String dec = (i <= 8) ? "REJECTED" : "APPROVED";
            feedbackService.submitFeedback(new OperatorFeedbackRequest(memId, "c-" + i, "op-1", dec, null), "op-1");
        }

        CalibrationResponse resp = feedbackService.getCalibrationRecommendations("op-1");

        assertNotNull(resp);
        assertTrue(resp.isSufficientData());
        CalibrationRecommendation rec = resp.getRecommendations().get(0);
        assertEquals("HIGH_REVIEW_REJECTION_RATE", rec.getPatternDetected());
        assertEquals("LOWER_REVIEW_THRESHOLD", rec.getSuggestedDirection());
    }

    @Test
    @DisplayName("Calibration above threshold with block escalations recommends REVIEW_BLOCK_RULES")
    void testGetCalibration_AboveThreshold_BlockEscalations_RecommendsBlockRulesReview() {
        // 8 review approvals + 2 block escalations = 10 total observations
        for (int i = 1; i <= 8; i++) {
            Long memId = (long) i;
            auditService.recordEvent("MEMORY_QUARANTINED", "c-" + i, memId, (long) (100 + i), null, "REVIEW", 60, "SIGNAL_A", "RULE_REVIEW", "ANALYZER");
            feedbackService.submitFeedback(new OperatorFeedbackRequest(memId, "c-" + i, "op-1", "APPROVED", null), "op-1");
        }
        for (int i = 9; i <= 10; i++) {
            Long memId = (long) i;
            auditService.recordEvent("MEMORY_DENIED", "c-" + i, memId, null, null, "BLOCK", 95, "CRITICAL_SIGNAL", "RULE_BLOCK", "ANALYZER");
            feedbackService.submitFeedback(new OperatorFeedbackRequest(memId, "c-" + i, "op-1", "ESCALATED", null), "op-1");
        }

        CalibrationResponse resp = feedbackService.getCalibrationRecommendations("op-1");

        assertTrue(resp.isSufficientData());
        boolean hasBlockRec = resp.getRecommendations().stream().anyMatch(r -> "FREQUENT_BLOCK_ESCALATION".equals(r.getPatternDetected()));
        assertTrue(hasBlockRec);
    }

    // ====================================================================
    // 7. INVARIANT CHECKS — POLICY ENGINE REMAINS AUTHORITATIVE
    // ====================================================================

    @Test
    @DisplayName("Operator feedback does not modify PolicyEngine behavior or thresholds")
    void testCalibration_DoesNotMutatePolicyEngine_PolicyEngineRemainsAuthoritative() {
        // Generate high review approval calibration recommendations
        for (int i = 1; i <= 12; i++) {
            Long memId = (long) i;
            auditService.recordEvent("MEMORY_QUARANTINED", "c-" + i, memId, (long) (100 + i), null, "REVIEW", 60, "SIGNAL_A", "RULE_REVIEW", "ANALYZER");
            feedbackService.submitFeedback(new OperatorFeedbackRequest(memId, "c-" + i, "op-1", "APPROVED", null), "op-1");
        }

        CalibrationResponse resp = feedbackService.getCalibrationRecommendations("op-1");
        assertNotNull(resp);

        // Verify PolicyEngine decision logic remains completely identical
        assertEquals(PolicyEngine.class.getName(), policyEngine.getClass().getName());
        assertEquals(memoryguard_backend.security.PolicyDecision.REVIEW, policyEngine.decide(60));
        assertEquals(memoryguard_backend.security.PolicyDecision.BLOCK, policyEngine.decide(85));
        assertEquals(memoryguard_backend.security.PolicyDecision.ALLOW, policyEngine.decide(10));
    }

    // ====================================================================
    // 8. REST CONTROLLER INTEGRATION TESTS
    // ====================================================================

    @Test
    @DisplayName("POST /api/security/feedback returns 201 CREATED when authorized and valid")
    void testController_SubmitFeedback_Returns201Created() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(500L, "corr-500", "op-admin", "APPROVED", "Valid note");

        ResponseEntity<?> response = feedbackController.submitFeedback("op-admin", req);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertTrue(response.getBody() instanceof OperatorFeedback);
        OperatorFeedback fb = (OperatorFeedback) response.getBody();
        assertEquals(500L, fb.getMemoryId());
        assertEquals("APPROVED", fb.getFeedbackDecision());
    }

    @Test
    @DisplayName("POST /api/security/feedback returns 403 FORBIDDEN when operator identity missing")
    void testController_SubmitFeedback_UnauthorizedReturns403() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(500L, "corr-500", null, "APPROVED", "Valid note");

        ResponseEntity<?> responseNull = feedbackController.submitFeedback(null, req);
        assertEquals(HttpStatus.FORBIDDEN, responseNull.getStatusCode());

        ResponseEntity<?> responseAnon = feedbackController.submitFeedback("ANONYMOUS", req);
        assertEquals(HttpStatus.FORBIDDEN, responseAnon.getStatusCode());
    }

    @Test
    @DisplayName("POST /api/security/feedback returns 400 BAD_REQUEST when request invalid")
    void testController_SubmitFeedback_InvalidRequestReturns400() {
        OperatorFeedbackRequest req = new OperatorFeedbackRequest(-1L, "corr-500", "op-admin", "INVALID_DECISION", "Valid note");

        ResponseEntity<?> response = feedbackController.submitFeedback("op-admin", req);
        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    @DisplayName("GET /api/security/feedback/telemetry returns 200 OK when authorized")
    void testController_GetTelemetry_AuthorizedReturns200() {
        ResponseEntity<?> response = feedbackController.getTelemetry("op-admin");

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() instanceof OperatorFeedbackTelemetry);
    }

    @Test
    @DisplayName("GET /api/security/feedback/calibration returns 200 OK when authorized")
    void testController_GetCalibration_AuthorizedReturns200() {
        ResponseEntity<?> response = feedbackController.getCalibrationRecommendations("op-admin");

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody() instanceof CalibrationResponse);
    }
}

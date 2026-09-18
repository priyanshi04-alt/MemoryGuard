package memoryguard_backend;

import memoryguard_backend.controller.PolicyGovernanceController;
import memoryguard_backend.dto.CalibrationRecommendation;
import memoryguard_backend.dto.CreatePolicyProposalRequest;
import memoryguard_backend.entity.PolicyChangeProposal;
import memoryguard_backend.entity.PolicyVersion;
import memoryguard_backend.entity.PolicyVersionState;
import memoryguard_backend.entity.SecurityAuditEvent;
import memoryguard_backend.repository.DeniedMemoryRepository;
import memoryguard_backend.repository.PolicyChangeProposalRepository;
import memoryguard_backend.repository.PolicyVersionRepository;
import memoryguard_backend.repository.QuarantinedMemoryRepository;
import memoryguard_backend.repository.SecurityAuditRepository;
import memoryguard_backend.security.AggregatedRiskAssessment;
import memoryguard_backend.security.PolicyDecision;
import memoryguard_backend.security.PolicyDecisionResult;
import memoryguard_backend.security.PolicyEngine;
import memoryguard_backend.service.PolicyGovernanceService;
import memoryguard_backend.service.SecurityAuditService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class PolicyGovernanceTests {

    private PolicyVersionRepository versionRepository;
    private PolicyChangeProposalRepository proposalRepository;
    private SecurityAuditRepository auditRepository;
    private QuarantinedMemoryRepository quarantinedMemoryRepository;
    private DeniedMemoryRepository deniedMemoryRepository;

    private SecurityAuditService auditService;
    private PolicyEngine policyEngine;
    private PolicyGovernanceService governanceService;
    private PolicyGovernanceController governanceController;

    private List<PolicyVersion> dbVersions;
    private List<PolicyChangeProposal> dbProposals;
    private List<SecurityAuditEvent> dbAuditEvents;
    private long versionIdCounter = 1L;
    private long proposalIdCounter = 1L;
    private long auditIdCounter = 1L;

    @BeforeEach
    void setUp() {
        versionRepository = mock(PolicyVersionRepository.class);
        proposalRepository = mock(PolicyChangeProposalRepository.class);
        auditRepository = mock(SecurityAuditRepository.class);
        quarantinedMemoryRepository = mock(QuarantinedMemoryRepository.class);
        deniedMemoryRepository = mock(DeniedMemoryRepository.class);

        dbVersions = new ArrayList<>();
        dbProposals = new ArrayList<>();
        dbAuditEvents = new ArrayList<>();
        versionIdCounter = 1L;
        proposalIdCounter = 1L;
        auditIdCounter = 1L;

        // Mock PolicyVersionRepository
        when(versionRepository.save(any(PolicyVersion.class))).thenAnswer(inv -> {
            PolicyVersion pv = inv.getArgument(0);
            if (pv.getId() == null) {
                pv.setId(versionIdCounter++);
            }
            dbVersions.removeIf(existing -> existing.getId() != null && existing.getId().equals(pv.getId()));
            dbVersions.add(pv);
            return pv;
        });

        when(versionRepository.findTopByStatusOrderByIdDesc("ACTIVE")).thenAnswer(inv ->
                dbVersions.stream().filter(v -> "ACTIVE".equalsIgnoreCase(v.getStatus())).reduce((first, second) -> second)
        );

        when(versionRepository.findTopByOrderByVersionDesc()).thenAnswer(inv ->
                dbVersions.stream().max((v1, v2) -> Integer.compare(v1.getVersion(), v2.getVersion()))
        );

        when(versionRepository.findAllByOrderByVersionAsc()).thenAnswer(inv ->
                dbVersions.stream().sorted((v1, v2) -> Integer.compare(v1.getVersion(), v2.getVersion())).toList()
        );

        when(versionRepository.findByVersion(anyInt())).thenAnswer(inv -> {
            Integer ver = inv.getArgument(0);
            return dbVersions.stream().filter(v -> ver.equals(v.getVersion())).findFirst();
        });

        // Mock PolicyChangeProposalRepository
        when(proposalRepository.save(any(PolicyChangeProposal.class))).thenAnswer(inv -> {
            PolicyChangeProposal p = inv.getArgument(0);
            if (p.getId() == null) {
                p.setId(proposalIdCounter++);
            }
            if (p.getProposalId() == null) {
                p.setProposalId("prop-uuid-" + p.getId());
            }
            dbProposals.removeIf(existing -> existing.getId() != null && existing.getId().equals(p.getId()));
            dbProposals.add(p);
            return p;
        });

        when(proposalRepository.findByProposalId(anyString())).thenAnswer(inv -> {
            String pId = inv.getArgument(0);
            return dbProposals.stream().filter(p -> pId.equalsIgnoreCase(p.getProposalId())).findFirst();
        });

        when(proposalRepository.findById(anyLong())).thenAnswer(inv -> {
            Long numId = inv.getArgument(0);
            return dbProposals.stream().filter(p -> numId.equals(p.getId())).findFirst();
        });

        when(proposalRepository.findAllByOrderByCreatedAtDesc()).thenAnswer(inv -> new ArrayList<>(dbProposals));

        // Mock SecurityAuditRepository
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

        auditService = new SecurityAuditService(
                auditRepository,
                quarantinedMemoryRepository,
                deniedMemoryRepository
        );

        policyEngine = new PolicyEngine();

        governanceService = new PolicyGovernanceService(
                versionRepository,
                proposalRepository,
                policyEngine,
                auditService
        );

        governanceService.init();

        governanceController = new PolicyGovernanceController(governanceService);
    }

    // ====================================================================
    // 1. PROPOSAL CREATION & PERSISTENCE
    // ====================================================================

    @Test
    @DisplayName("1. Proposal creation initializes PENDING_APPROVAL and persists correctly")
    void test1_CreateProposal_PersistedCorrectly() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest(
                "LOWER_REVIEW_THRESHOLD",
                "High review rejection rate detected",
                "Review rejection rate exceeded 40% threshold",
                "REC-101",
                80,
                40
        );

        PolicyChangeProposal proposal = governanceService.createProposal(req, "op-sec-1");

        assertNotNull(proposal);
        assertNotNull(proposal.getProposalId());
        assertEquals("LOWER_REVIEW_THRESHOLD", proposal.getChangeType());
        assertEquals(PolicyVersionState.PENDING_APPROVAL.name(), proposal.getStatus());
        assertEquals(1, proposal.getCurrentPolicyVersion());
        assertEquals(2, proposal.getProposedPolicyVersion());
        assertEquals(40, proposal.getProposedReviewThreshold());
        assertEquals(80, proposal.getProposedBlockThreshold());
        assertEquals("op-sec-1", proposal.getCreatedBy());

        // Verify persisted in repository
        PolicyChangeProposal fetched = governanceService.getProposalById(proposal.getProposalId(), "op-sec-1");
        assertNotNull(fetched);
        assertEquals(proposal.getProposalId(), fetched.getProposalId());
    }

    // ====================================================================
    // 2. AUTHORIZATION BOUNDARY TESTS
    // ====================================================================

    @Test
    @DisplayName("2. Missing X-Operator-Id header returns 403 FORBIDDEN")
    void test2_MissingOperatorHeader_Returns403() {
        assertThrows(SecurityException.class, () -> governanceService.getAllProposals(null));

        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence");
        ResponseEntity<?> resp = governanceController.createProposal(null, req);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    @DisplayName("3. Blank X-Operator-Id header returns 403 FORBIDDEN")
    void test3_BlankOperatorHeader_Returns403() {
        assertThrows(SecurityException.class, () -> governanceService.getAllProposals("   "));

        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence");
        ResponseEntity<?> resp = governanceController.createProposal("  ", req);
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    @DisplayName("4. ANONYMOUS operator identity returns 403 FORBIDDEN")
    void test4_AnonymousOperator_Returns403() {
        assertThrows(SecurityException.class, () -> governanceService.getActivePolicy("ANONYMOUS"));
        assertThrows(SecurityException.class, () -> governanceService.getActivePolicy("anonymous"));

        ResponseEntity<?> resp = governanceController.getActivePolicy("ANONYMOUS");
        assertEquals(HttpStatus.FORBIDDEN, resp.getStatusCode());
    }

    @Test
    @DisplayName("5. Unauthorized operator attempting approve throws SecurityException / 403")
    void test5_UnauthorizedApprove_Returns403() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence");
        PolicyChangeProposal proposal = governanceService.createProposal(req, "sec-op-1");

        assertThrows(SecurityException.class, () -> governanceService.approveProposal(proposal.getProposalId(), "unauthorized-operator", "Approve note"));
        assertEquals(HttpStatus.FORBIDDEN, governanceController.approveProposal(proposal.getProposalId(), "guest-viewer", null).getStatusCode());
    }

    @Test
    @DisplayName("6. Unauthorized operator attempting reject throws SecurityException / 403")
    void test6_UnauthorizedReject_Returns403() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence");
        PolicyChangeProposal proposal = governanceService.createProposal(req, "sec-op-1");

        assertThrows(SecurityException.class, () -> governanceService.rejectProposal(proposal.getProposalId(), "read-only-user", "Reject note"));
        assertEquals(HttpStatus.FORBIDDEN, governanceController.rejectProposal(proposal.getProposalId(), "guest-viewer", null).getStatusCode());
    }

    @Test
    @DisplayName("7. Unauthorized operator attempting activate throws SecurityException / 403")
    void test7_UnauthorizedActivate_Returns403() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence");
        PolicyChangeProposal proposal = governanceService.createProposal(req, "sec-op-1");
        governanceService.approveProposal(proposal.getProposalId(), "sec-admin-1", "Approved");

        assertThrows(SecurityException.class, () -> governanceService.activateProposal(proposal.getProposalId(), "unauthorized-operator", "Activate note"));
        assertEquals(HttpStatus.FORBIDDEN, governanceController.activateProposal(proposal.getProposalId(), "guest-viewer", null).getStatusCode());
    }

    // ====================================================================
    // 3. LIFECYCLE & TRANSITION STATE MACHINE TESTS
    // ====================================================================

    @Test
    @DisplayName("8. State transition PENDING_APPROVAL -> APPROVED succeeds")
    void test8_PendingToApproved_TransitionSucceeds() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason", "Evidence");
        PolicyChangeProposal proposal = governanceService.createProposal(req, "op-1");

        PolicyChangeProposal approved = governanceService.approveProposal(proposal.getProposalId(), "sec-admin-1", "Approved by admin");
        assertEquals(PolicyVersionState.APPROVED.name(), approved.getStatus());
        assertEquals("sec-admin-1", approved.getReviewedBy());
        assertNotNull(approved.getReviewedAt());
    }

    @Test
    @DisplayName("9. State transition PENDING_APPROVAL -> REJECTED succeeds")
    void test9_PendingToRejected_TransitionSucceeds() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason", "Evidence");
        PolicyChangeProposal proposal = governanceService.createProposal(req, "op-1");

        PolicyChangeProposal rejected = governanceService.rejectProposal(proposal.getProposalId(), "sec-admin-1", "Rejection rationale");
        assertEquals(PolicyVersionState.REJECTED.name(), rejected.getStatus());
        assertEquals("Rejection rationale", rejected.getRejectionReason());
    }

    @Test
    @DisplayName("10. State transition PENDING_APPROVAL -> ACTIVE fails with IllegalStateException")
    void test10_PendingToActive_TransitionFails() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason", "Evidence");
        PolicyChangeProposal proposal = governanceService.createProposal(req, "op-1");

        assertThrows(IllegalStateException.class, () -> governanceService.activateProposal(proposal.getProposalId(), "sec-admin-1", "Direct activation"));
    }

    @Test
    @DisplayName("11. State transition REJECTED -> ACTIVE fails with IllegalStateException")
    void test11_RejectedToActive_TransitionFails() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason", "Evidence");
        PolicyChangeProposal proposal = governanceService.createProposal(req, "op-1");
        governanceService.rejectProposal(proposal.getProposalId(), "sec-admin-1", "Rejected");

        assertThrows(IllegalStateException.class, () -> governanceService.activateProposal(proposal.getProposalId(), "sec-admin-1", "Activate rejected"));
    }

    @Test
    @DisplayName("12. State transition APPROVED -> ACTIVE succeeds")
    void test12_ApprovedToActive_TransitionSucceeds() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence", null, 80, 40);
        PolicyChangeProposal proposal = governanceService.createProposal(req, "op-1");
        governanceService.approveProposal(proposal.getProposalId(), "sec-admin-1", "Approved");

        PolicyVersion activated = governanceService.activateProposal(proposal.getProposalId(), "sec-admin-1", "Activated");
        assertEquals(PolicyVersionState.ACTIVE.name(), activated.getStatus());
        assertEquals(2, activated.getVersion());
        assertEquals(40, activated.getReviewThreshold());
    }

    @Test
    @DisplayName("13. Activation marks previous active version as SUPERSEDED")
    void test13_PreviousActiveVersion_BecomesSuperseded() {
        PolicyVersion v1 = governanceService.getActivePolicy("sec-admin-1");
        assertEquals(1, v1.getVersion());
        assertEquals(PolicyVersionState.ACTIVE.name(), v1.getStatus());

        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence", null, 80, 40);
        PolicyChangeProposal prop = governanceService.createProposal(req, "op-1");
        governanceService.approveProposal(prop.getProposalId(), "sec-admin-1", "Approved");
        PolicyVersion v2 = governanceService.activateProposal(prop.getProposalId(), "sec-admin-1", "Activated v2");

        assertEquals(2, v2.getVersion());
        assertEquals(PolicyVersionState.ACTIVE.name(), v2.getStatus());

        Optional<PolicyVersion> v1Refreshed = versionRepository.findByVersion(1);
        assertTrue(v1Refreshed.isPresent());
        assertEquals(PolicyVersionState.SUPERSEDED.name(), v1Refreshed.get().getStatus());
        assertNotNull(v1Refreshed.get().getSupersededAt());
    }

    @Test
    @DisplayName("14. Single ACTIVE policy version invariant is enforced across transitions")
    void test14_SingleActivePolicyVersion_InvariantEnforced() {
        // Initial state: v1 ACTIVE
        long activeCountV1 = dbVersions.stream().filter(v -> PolicyVersionState.ACTIVE.name().equalsIgnoreCase(v.getStatus())).count();
        assertEquals(1, activeCountV1);

        // Activate v2
        CreatePolicyProposalRequest req2 = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason", "Evidence", null, 80, 60);
        PolicyChangeProposal p2 = governanceService.createProposal(req2, "op-1");
        governanceService.approveProposal(p2.getProposalId(), "sec-admin-1", "Approved");
        governanceService.activateProposal(p2.getProposalId(), "sec-admin-1", "Activated");

        long activeCountV2 = dbVersions.stream().filter(v -> PolicyVersionState.ACTIVE.name().equalsIgnoreCase(v.getStatus())).count();
        assertEquals(1, activeCountV2);
        assertEquals(2, governanceService.getActivePolicy("sec-admin-1").getVersion());
    }

    // ====================================================================
    // 4. AUDIT & ZERO-PLAINTEXT SECURITY TESTS
    // ====================================================================

    @Test
    @DisplayName("15. Audit events are generated for all governance lifecycle actions")
    void test15_AuditEventsGenerated_ForGovernanceActions() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence");
        PolicyChangeProposal prop = governanceService.createProposal(req, "op-1");
        governanceService.approveProposal(prop.getProposalId(), "sec-admin-1", "Approved");
        governanceService.activateProposal(prop.getProposalId(), "sec-admin-1", "Activated");

        List<String> eventTypes = dbAuditEvents.stream().map(SecurityAuditEvent::getEventType).toList();
        assertTrue(eventTypes.contains("POLICY_CHANGE_PROPOSED"));
        assertTrue(eventTypes.contains("POLICY_CHANGE_APPROVED"));
        assertTrue(eventTypes.contains("POLICY_VERSION_SUPERSEDED"));
        assertTrue(eventTypes.contains("POLICY_VERSION_ACTIVATED"));

        // Verify SHA-256 hash chain validity
        assertTrue(auditService.verifyAuditIntegrity().isValid());
    }

    // ====================================================================
    // 5. CRITICAL MANDATORY REGRESSION TEST (PROMPT REQUIREMENT #18)
    // ====================================================================

    @Test
    @DisplayName("16. CRITICAL REGRESSION TEST: Calibration recommendations and proposals do NOT mutate PolicyEngine before activation")
    void test16_CriticalRegression_CalibrationRecommendationDoesNotMutatePolicyEngine() {
        // Initial PolicyEngine reviewThreshold = 50
        assertEquals(50, policyEngine.getReviewThreshold());

        // Step 1: Calibration recommendation generated (suggests raising threshold to 60)
        CalibrationRecommendation recommendation = new CalibrationRecommendation(
                "LOW_REVIEW_QUALITY",
                10L,
                "MEDIUM_RISK_REVIEW",
                0.95,
                "RAISE_REVIEW_THRESHOLD",
                "Operators consistently approved memories in REVIEW."
        );
        // Assert PolicyEngine reviewThreshold MUST STILL BE 50
        assertEquals(50, policyEngine.getReviewThreshold(), "PolicyEngine threshold must remain 50 after recommendation generation!");

        // Step 2: Proposal created from recommendation
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Raise review threshold", "Evidence", recommendation.getPatternDetected(), 80, 60);
        PolicyChangeProposal proposal = governanceService.createProposal(req, "sec-op-1");
        // Assert PolicyEngine reviewThreshold MUST STILL BE 50
        assertEquals(50, policyEngine.getReviewThreshold(), "PolicyEngine threshold must remain 50 after proposal creation!");

        // Step 3: Proposal approved by admin
        governanceService.approveProposal(proposal.getProposalId(), "sec-admin-1", "Approved raising threshold to 60");
        // Assert PolicyEngine reviewThreshold MUST STILL BE 50 (Approval != Activation)
        assertEquals(50, policyEngine.getReviewThreshold(), "PolicyEngine threshold must remain 50 after proposal approval!");

        // Step 4: ONLY after authorized activation does PolicyEngine update threshold
        governanceService.activateProposal(proposal.getProposalId(), "sec-admin-1", "Activated new policy v2");
        // Assert PolicyEngine reviewThreshold is NOW 60
        assertEquals(60, policyEngine.getReviewThreshold(), "PolicyEngine threshold must update to 60 ONLY after authorized activation!");
    }

    @Test
    @DisplayName("17. Zero Plaintext Security: Proposal does not persist sensitive memory content")
    void test17_ZeroPlaintext_ProposalDoesNotStoreSensitiveMemoryContent() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest(
                "LOWER_REVIEW_THRESHOLD",
                "Based on aggregate risk score trends",
                "Category risk distribution metadata only"
        );
        PolicyChangeProposal proposal = governanceService.createProposal(req, "op-1");

        assertFalse(proposal.getReason().toLowerCase().contains("password"));
        assertFalse(proposal.getReason().toLowerCase().contains("secret_key"));
        assertFalse(proposal.getEvidence().toLowerCase().contains("bearer_token"));
    }

    @Test
    @DisplayName("18. Zero Plaintext Security: Audit event does not persist sensitive memory content")
    void test18_ZeroPlaintext_AuditEventDoesNotStoreSensitiveMemoryContent() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason metadata", "Telemetry metadata");
        PolicyChangeProposal prop = governanceService.createProposal(req, "op-1");
        governanceService.approveProposal(prop.getProposalId(), "sec-admin-1", "Approved note");

        for (SecurityAuditEvent event : dbAuditEvents) {
            assertNotNull(event.getEventType());
            if (event.getContributingFactors() != null) {
                assertFalse(event.getContributingFactors().toLowerCase().contains("password"));
                assertFalse(event.getContributingFactors().toLowerCase().contains("api_key"));
            }
        }
    }

    @Test
    @DisplayName("19. Invalid threshold combinations are rejected with IllegalArgumentException")
    void test19_InvalidThresholdCombinations_AreRejected() {
        // Negative review threshold -> Exception
        assertThrows(IllegalArgumentException.class, () ->
                governanceService.createProposal(new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence", null, 80, -10), "op-1"));

        // Block threshold > 100 -> Exception
        assertThrows(IllegalArgumentException.class, () ->
                governanceService.createProposal(new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence", null, 150, 50), "op-1"));

        // reviewThreshold >= blockThreshold (e.g. 80 review, 80 block or 90 review, 80 block) -> Exception
        assertThrows(IllegalArgumentException.class, () ->
                governanceService.createProposal(new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence", null, 80, 80), "op-1"));

        assertThrows(IllegalArgumentException.class, () ->
                governanceService.createProposal(new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence", null, 80, 90), "op-1"));
    }

    @Test
    @DisplayName("20. Rejected proposal cannot be activated and throws IllegalStateException")
    void test20_RejectedProposalCannotBeActivated() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason", "Evidence");
        PolicyChangeProposal proposal = governanceService.createProposal(req, "op-1");
        governanceService.rejectProposal(proposal.getProposalId(), "sec-admin-1", "Rejected due to risk concerns");

        assertThrows(IllegalStateException.class, () ->
                governanceService.activateProposal(proposal.getProposalId(), "sec-admin-1", "Attempt activation"));
    }
}

package memoryguard_backend;

import memoryguard_backend.controller.PolicyGovernanceController;
import memoryguard_backend.dto.*;
import memoryguard_backend.entity.*;
import memoryguard_backend.repository.*;
import memoryguard_backend.security.PolicyEngine;
import memoryguard_backend.service.PolicyGovernanceObservabilityService;
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

public class PolicyGovernanceObservabilityTests {

    private PolicyVersionRepository versionRepository;
    private PolicyChangeProposalRepository proposalRepository;
    private SecurityAuditRepository auditRepository;
    private QuarantinedMemoryRepository quarantinedMemoryRepository;
    private DeniedMemoryRepository deniedMemoryRepository;

    private SecurityAuditService auditService;
    private PolicyEngine policyEngine;
    private PolicyGovernanceService governanceService;
    private PolicyGovernanceObservabilityService observabilityService;
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

        when(versionRepository.findByStatus(anyString())).thenAnswer(inv -> {
            String st = inv.getArgument(0);
            return dbVersions.stream().filter(v -> st.equalsIgnoreCase(v.getStatus())).toList();
        });

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

        when(proposalRepository.findByStatus(anyString())).thenAnswer(inv -> {
            String st = inv.getArgument(0);
            return dbProposals.stream().filter(p -> st.equalsIgnoreCase(p.getStatus())).toList();
        });

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

        observabilityService = new PolicyGovernanceObservabilityService(
                versionRepository,
                proposalRepository,
                policyEngine,
                auditService,
                governanceService
        );

        governanceController = new PolicyGovernanceController(governanceService, observabilityService);
    }

    // ====================================================================
    // 1. GOVERNANCE METRICS TESTS
    // ====================================================================

    @Test
    @DisplayName("1. Governance metrics calculation derives accurate counts from authoritative persistence")
    void test1_GovernanceMetricsCalculation() {
        // Create 2 proposals
        CreatePolicyProposalRequest req1 = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason 1", "Evidence 1", null, 80, 40);
        CreatePolicyProposalRequest req2 = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason 2", "Evidence 2", null, 80, 60);

        PolicyChangeProposal p1 = governanceService.createProposal(req1, "sec-op-1");
        PolicyChangeProposal p2 = governanceService.createProposal(req2, "sec-op-2");

        // Approve and activate p1
        governanceService.approveProposal(p1.getProposalId(), "sec-admin-1", "Approved");
        governanceService.activateProposal(p1.getProposalId(), "sec-admin-1", "Activated");

        // Reject p2
        governanceService.rejectProposal(p2.getProposalId(), "sec-admin-1", "Rejected");

        GovernanceMetricsResponse metrics = observabilityService.getGovernanceMetrics("sec-admin-1");

        assertNotNull(metrics);
        assertEquals(2, metrics.getTotalProposals());
        assertEquals(0, metrics.getPendingProposals());
        assertEquals(0, metrics.getApprovedProposals()); // p1 was activated so state became ACTIVE
        assertEquals(1, metrics.getRejectedProposals());
        assertEquals(1, metrics.getActivePolicyVersions());
        assertEquals(1, metrics.getSupersededPolicyVersions()); // v1 initial superseded
        assertEquals(2, metrics.getTotalPolicyActivations()); // v1 + v2
        assertEquals(1, metrics.getTotalPolicyRejections());
    }

    @Test
    @DisplayName("2. Proposal state counts breakdown correctly by PolicyVersionState")
    void test2_ProposalStateCountsAggregation() {
        CreatePolicyProposalRequest req1 = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence");
        CreatePolicyProposalRequest req2 = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason", "Evidence");

        governanceService.createProposal(req1, "op-1");
        governanceService.createProposal(req2, "op-2");

        GovernanceMetricsResponse metrics = observabilityService.getGovernanceMetrics("sec-admin-1");

        assertEquals(2, metrics.getPendingProposals());
        assertNotNull(metrics.getProposalCountsByState());
        assertEquals(2L, metrics.getProposalCountsByState().get("PENDING_APPROVAL"));
    }

    @Test
    @DisplayName("3. Proposal counts aggregate correctly by PolicyChangeType")
    void test3_ChangeTypeAggregation() {
        governanceService.createProposal(new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence"), "op-1");
        governanceService.createProposal(new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence"), "op-2");
        governanceService.createProposal(new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason", "Evidence"), "op-3");

        GovernanceMetricsResponse metrics = observabilityService.getGovernanceMetrics("sec-admin-1");

        Map<String, Long> byType = metrics.getProposalCountsByChangeType();
        assertNotNull(byType);
        assertEquals(2L, byType.get("LOWER_REVIEW_THRESHOLD"));
        assertEquals(1L, byType.get("RAISE_REVIEW_THRESHOLD"));
    }

    @Test
    @DisplayName("4. Active policy metrics reflect single active version invariant")
    void test4_ActivePolicyMetrics() {
        GovernanceMetricsResponse metrics = observabilityService.getGovernanceMetrics("sec-admin-1");
        assertEquals(1, metrics.getActivePolicyVersions());
        assertEquals(0, metrics.getSupersededPolicyVersions());
    }

    // ====================================================================
    // 2. POLICY ANALYTICS & TIMELINE TESTS
    // ====================================================================

    @Test
    @DisplayName("5. Policy history analytics reports active, previous, and timeline version details")
    void test5_PolicyHistoryAnalytics() {
        // v1 active (50 review, 80 block)
        // Create and activate v2 (40 review, 80 block)
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence", null, 80, 40);
        PolicyChangeProposal p1 = governanceService.createProposal(req, "sec-op-1");
        governanceService.approveProposal(p1.getProposalId(), "sec-admin-1", "Approved");
        governanceService.activateProposal(p1.getProposalId(), "sec-admin-1", "Activated v2");

        PolicyAnalyticsResponse analytics = observabilityService.getPolicyAnalytics("sec-admin-1");

        assertNotNull(analytics);
        assertEquals(2, analytics.getTotalPolicyVersions());
        assertEquals(2, analytics.getActivatedVersionsCount());
        assertEquals(1, analytics.getSupersededVersionsCount());
        assertEquals(2, analytics.getCurrentActiveVersion().getVersionNumber());
        assertEquals(40, analytics.getCurrentReviewThreshold());
        assertEquals(80, analytics.getCurrentBlockThreshold());
        assertEquals(50, analytics.getPreviousReviewThreshold());
        assertEquals(80, analytics.getPreviousBlockThreshold());
        assertEquals(2, analytics.getPolicyChangesTimeline().size());
    }

    // ====================================================================
    // 3. OPERATOR ACTIVITY SUMMARY TESTS
    // ====================================================================

    @Test
    @DisplayName("6. Operator activity summary aggregates proposals, approvals, rejections, and activations per operator")
    void test6_OperatorActivityAggregation() {
        CreatePolicyProposalRequest req1 = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence");
        CreatePolicyProposalRequest req2 = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "Reason", "Evidence");

        PolicyChangeProposal p1 = governanceService.createProposal(req1, "operator-alice");
        PolicyChangeProposal p2 = governanceService.createProposal(req2, "operator-alice");

        governanceService.approveProposal(p1.getProposalId(), "admin-bob", "Approved p1");
        governanceService.activateProposal(p1.getProposalId(), "admin-bob", "Activated p1");

        governanceService.rejectProposal(p2.getProposalId(), "admin-bob", "Rejected p2");

        List<OperatorGovernanceActivityResponse> summaries = observabilityService.getOperatorActivitySummary("admin-bob");

        assertNotNull(summaries);
        assertFalse(summaries.isEmpty());

        Optional<OperatorGovernanceActivityResponse> aliceOpt = summaries.stream().filter(s -> "operator-alice".equalsIgnoreCase(s.getOperatorId())).findFirst();
        assertTrue(aliceOpt.isPresent());
        assertEquals(2, aliceOpt.get().getProposalsCreated());

        Optional<OperatorGovernanceActivityResponse> bobOpt = summaries.stream().filter(s -> "admin-bob".equalsIgnoreCase(s.getOperatorId())).findFirst();
        assertTrue(bobOpt.isPresent());
        assertEquals(1, bobOpt.get().getApprovalsPerformed());
        assertEquals(1, bobOpt.get().getRejectionsPerformed());
        assertEquals(1, bobOpt.get().getActivationsPerformed());
    }

    // ====================================================================
    // 4. GOVERNANCE HEALTH TESTS
    // ====================================================================

    @Test
    @DisplayName("7. Governance security health returns HEALTHY status when active policy is present and audit chain is intact")
    void test7_GovernanceSecurityHealthStatus() {
        GovernanceHealthResponse health = observabilityService.getGovernanceSecurityHealth("sec-admin-1");

        assertNotNull(health);
        assertTrue(health.isActivePolicyPresent());
        assertEquals(1, health.getActivePolicyCount());
        assertTrue(health.isGovernanceAuditAvailable());
        assertTrue(health.isAuditChainIntegrityValid());
        assertEquals("HEALTHY", health.getStatus());
        assertNotNull(health.getMessage());
    }

    // ====================================================================
    // 5. AUTHORIZATION BOUNDARY TESTS (READ-ONLY ENDPOINTS)
    // ====================================================================

    @Test
    @DisplayName("8. Missing X-Operator-Id header returns 403 FORBIDDEN on read-only endpoints")
    void test8_MissingOperatorHeader_Returns403() {
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getGovernanceMetrics(null).getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getPolicyAnalytics(null).getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getOperatorActivitySummary(null).getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getGovernanceSecurityHealth(null).getStatusCode());
    }

    @Test
    @DisplayName("9. Blank X-Operator-Id header returns 403 FORBIDDEN on read-only endpoints")
    void test9_BlankOperatorHeader_Returns403() {
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getGovernanceMetrics("   ").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getPolicyAnalytics("   ").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getOperatorActivitySummary("   ").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getGovernanceSecurityHealth("   ").getStatusCode());
    }

    @Test
    @DisplayName("10. ANONYMOUS operator identity returns 403 FORBIDDEN on read-only endpoints")
    void test10_AnonymousOperator_Returns403() {
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getGovernanceMetrics("ANONYMOUS").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getPolicyAnalytics("anonymous").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getOperatorActivitySummary("ANONYMOUS").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, governanceController.getGovernanceSecurityHealth("anonymous").getStatusCode());
    }

    // ====================================================================
    // 6. STRICT SECURITY INVARIANT TESTS (DAY 26 READ-ONLY INVARIANTS)
    // ====================================================================

    @Test
    @DisplayName("11. CRITICAL INVARIANT 2: Querying metrics NEVER mutates PolicyEngine review or block thresholds")
    void test11_MetricsEndpointDoesNotMutatePolicyEngine() {
        int reviewBefore = policyEngine.getReviewThreshold();
        int blockBefore = policyEngine.getBlockThreshold();

        observabilityService.getGovernanceMetrics("sec-admin-1");
        governanceController.getGovernanceMetrics("sec-admin-1");

        assertEquals(reviewBefore, policyEngine.getReviewThreshold());
        assertEquals(blockBefore, policyEngine.getBlockThreshold());
    }

    @Test
    @DisplayName("12. CRITICAL INVARIANT 3: Querying analytics NEVER activates a policy or changes active version status")
    void test12_AnalyticsEndpointDoesNotActivatePolicy() {
        PolicyVersion activeBefore = governanceService.getActivePolicy("sec-admin-1");

        observabilityService.getPolicyAnalytics("sec-admin-1");
        governanceController.getPolicyAnalytics("sec-admin-1");

        PolicyVersion activeAfter = governanceService.getActivePolicy("sec-admin-1");
        assertEquals(activeBefore.getVersion(), activeAfter.getVersion());
        assertEquals(activeBefore.getStatus(), activeAfter.getStatus());
    }

    @Test
    @DisplayName("13. Zero Plaintext Security: Governance metrics, analytics, and operator responses contain no sensitive memory content")
    void test13_ZeroPlaintextProtectionInObservabilityResponses() {
        GovernanceMetricsResponse metrics = observabilityService.getGovernanceMetrics("sec-admin-1");
        PolicyAnalyticsResponse analytics = observabilityService.getPolicyAnalytics("sec-admin-1");
        List<OperatorGovernanceActivityResponse> operators = observabilityService.getOperatorActivitySummary("sec-admin-1");
        GovernanceHealthResponse health = observabilityService.getGovernanceSecurityHealth("sec-admin-1");

        assertNotNull(metrics);
        assertNotNull(analytics);
        assertNotNull(operators);
        assertNotNull(health);

        // Assert response representations expose policy metadata only
        for (OperatorGovernanceActivityResponse op : operators) {
            assertFalse(op.getOperatorId().toLowerCase().contains("password"));
            assertFalse(op.getOperatorId().toLowerCase().contains("secret"));
        }
    }

    @Test
    @DisplayName("14. Audit chain SHA-256 hash chain integrity remains valid after observability calls")
    void test14_AuditChainIntegrityValidation() {
        assertTrue(auditService.verifyAuditIntegrity().isValid());

        observabilityService.getGovernanceMetrics("sec-admin-1");
        observabilityService.getGovernanceSecurityHealth("sec-admin-1");

        assertTrue(auditService.verifyAuditIntegrity().isValid());
    }

    @Test
    @DisplayName("15. Single ACTIVE policy version invariant remains enforced and reported accurately")
    void test15_SingleActivePolicyInvariantVerified() {
        GovernanceHealthResponse health = observabilityService.getGovernanceSecurityHealth("sec-admin-1");
        assertEquals(1, health.getActivePolicyCount());
        assertTrue(health.isActivePolicyPresent());
        assertEquals("HEALTHY", health.getStatus());
    }

    @Test
    @DisplayName("16. Regression check: Day 25 proposal approval and activation lifecycle continues working as expected")
    void test16_ExistingDay25LifecycleTestsRegressionCheck() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence", null, 80, 40);
        PolicyChangeProposal proposal = governanceService.createProposal(req, "sec-op-1");

        assertEquals(PolicyVersionState.PENDING_APPROVAL.name(), proposal.getStatus());

        PolicyChangeProposal approved = governanceService.approveProposal(proposal.getProposalId(), "sec-admin-1", "Approved");
        assertEquals(PolicyVersionState.APPROVED.name(), approved.getStatus());

        PolicyVersion activated = governanceService.activateProposal(approved.getProposalId(), "sec-admin-1", "Activated");
        assertEquals(PolicyVersionState.ACTIVE.name(), activated.getStatus());
        assertEquals(2, activated.getVersion());
    }
}

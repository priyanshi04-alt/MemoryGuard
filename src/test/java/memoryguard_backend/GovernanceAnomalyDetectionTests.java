package memoryguard_backend;

import memoryguard_backend.controller.GovernanceAnomalyController;
import memoryguard_backend.dto.CreatePolicyProposalRequest;
import memoryguard_backend.dto.GovernanceAnomalySummaryResponse;
import memoryguard_backend.dto.GovernanceFindingResponse;
import memoryguard_backend.entity.*;
import memoryguard_backend.repository.*;
import memoryguard_backend.security.PolicyEngine;
import memoryguard_backend.security.governance.anomaly.GovernanceAnomalyThresholds;
import memoryguard_backend.service.GovernanceAnomalyDetectionService;
import memoryguard_backend.service.PolicyGovernanceService;
import memoryguard_backend.service.SecurityAuditService;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class GovernanceAnomalyDetectionTests {

    private PolicyVersionRepository versionRepository;
    private PolicyChangeProposalRepository proposalRepository;
    private GovernanceSecurityFindingRepository findingRepository;
    private SecurityAuditRepository auditRepository;
    private QuarantinedMemoryRepository quarantinedMemoryRepository;
    private DeniedMemoryRepository deniedMemoryRepository;

    private SecurityAuditService auditService;
    private PolicyEngine policyEngine;
    private PolicyGovernanceService governanceService;
    private GovernanceAnomalyThresholds thresholds;
    private GovernanceAnomalyDetectionService anomalyService;
    private GovernanceAnomalyController anomalyController;

    private List<PolicyVersion> dbVersions;
    private List<PolicyChangeProposal> dbProposals;
    private List<GovernanceSecurityFinding> dbFindings;
    private List<SecurityAuditEvent> dbAuditEvents;
    private long versionIdCounter = 1L;
    private long proposalIdCounter = 1L;
    private long findingIdCounter = 1L;
    private long auditIdCounter = 1L;

    @BeforeEach
    void setUp() {
        versionRepository = mock(PolicyVersionRepository.class);
        proposalRepository = mock(PolicyChangeProposalRepository.class);
        findingRepository = mock(GovernanceSecurityFindingRepository.class);
        auditRepository = mock(SecurityAuditRepository.class);
        quarantinedMemoryRepository = mock(QuarantinedMemoryRepository.class);
        deniedMemoryRepository = mock(DeniedMemoryRepository.class);

        dbVersions = new ArrayList<>();
        dbProposals = new ArrayList<>();
        dbFindings = new ArrayList<>();
        dbAuditEvents = new ArrayList<>();
        versionIdCounter = 1L;
        proposalIdCounter = 1L;
        findingIdCounter = 1L;
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

        // Mock GovernanceSecurityFindingRepository
        when(findingRepository.save(any(GovernanceSecurityFinding.class))).thenAnswer(inv -> {
            GovernanceSecurityFinding f = inv.getArgument(0);
            if (f.getId() == null) {
                f.setId(findingIdCounter++);
            }
            if (f.getFindingId() == null) {
                f.setFindingId("finding-uuid-" + f.getId());
            }
            dbFindings.removeIf(existing -> existing.getId() != null && existing.getId().equals(f.getId()));
            dbFindings.add(f);
            return f;
        });

        when(findingRepository.findByFindingId(anyString())).thenAnswer(inv -> {
            String fId = inv.getArgument(0);
            return dbFindings.stream().filter(f -> fId.equalsIgnoreCase(f.getFindingId())).findFirst();
        });

        when(findingRepository.findById(anyLong())).thenAnswer(inv -> {
            Long numId = inv.getArgument(0);
            return dbFindings.stream().filter(f -> numId.equals(f.getId())).findFirst();
        });

        when(findingRepository.findAllByOrderByDetectedAtDesc()).thenAnswer(inv -> new ArrayList<>(dbFindings));

        when(findingRepository.findByStatus(anyString())).thenAnswer(inv -> {
            String st = inv.getArgument(0);
            return dbFindings.stream().filter(f -> st.equalsIgnoreCase(f.getStatus())).toList();
        });

        when(findingRepository.findByAnomalyType(anyString())).thenAnswer(inv -> {
            String type = inv.getArgument(0);
            return dbFindings.stream().filter(f -> type.equalsIgnoreCase(f.getAnomalyType())).toList();
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

        thresholds = new GovernanceAnomalyThresholds();

        anomalyService = new GovernanceAnomalyDetectionService(
                findingRepository,
                proposalRepository,
                versionRepository,
                auditService,
                governanceService,
                thresholds,
                policyEngine
        );

        anomalyController = new GovernanceAnomalyController(anomalyService);
    }

    // ====================================================================
    // 1. DETERMINISTIC ANOMALY DETECTION TESTS
    // ====================================================================

    @Test
    @DisplayName("1. RAPID_GOVERNANCE_ACTIVITY: Detects unusually large number of governance actions by single operator")
    void test1_RapidGovernanceActivityDetection() {
        // Create 6 proposals rapidly by operator-spam
        for (int i = 0; i < 6; i++) {
            governanceService.createProposal(
                    new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason " + i, "Evidence " + i, null, 80, 40),
                    "operator-spam"
            );
        }

        List<GovernanceSecurityFinding> findings = anomalyService.scanForAnomalies("sec-admin-1");

        assertNotNull(findings);
        Optional<GovernanceSecurityFinding> rapidOpt = findings.stream()
                .filter(f -> GovernanceAnomalyType.RAPID_GOVERNANCE_ACTIVITY.name().equals(f.getAnomalyType()))
                .findFirst();

        assertTrue(rapidOpt.isPresent(), "RAPID_GOVERNANCE_ACTIVITY finding should be detected!");
        assertEquals("HIGH", rapidOpt.get().getSeverity());
        assertEquals("operator-spam", rapidOpt.get().getOperatorId());
        assertTrue(rapidOpt.get().getEvidence().contains("actionCount"));
    }

    @Test
    @DisplayName("2. RAPID_POLICY_ACTIVATION: Detects multiple policy activations in short observation window")
    void test2_RapidPolicyActivationDetection() {
        // Create & activate proposal 1 -> v2
        CreatePolicyProposalRequest req1 = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "R1", "E1", null, 80, 40);
        PolicyChangeProposal p1 = governanceService.createProposal(req1, "sec-op-1");
        governanceService.approveProposal(p1.getProposalId(), "sec-admin-1", "Approve p1");
        governanceService.activateProposal(p1.getProposalId(), "sec-admin-1", "Activate p1");

        // Create & activate proposal 2 -> v3
        CreatePolicyProposalRequest req2 = new CreatePolicyProposalRequest("RAISE_REVIEW_THRESHOLD", "R2", "E2", null, 80, 60);
        PolicyChangeProposal p2 = governanceService.createProposal(req2, "sec-op-1");
        governanceService.approveProposal(p2.getProposalId(), "sec-admin-1", "Approve p2");
        governanceService.activateProposal(p2.getProposalId(), "sec-admin-1", "Activate p2");

        List<GovernanceSecurityFinding> findings = anomalyService.scanForAnomalies("sec-admin-1");

        Optional<GovernanceSecurityFinding> rapidActOpt = findings.stream()
                .filter(f -> GovernanceAnomalyType.RAPID_POLICY_ACTIVATION.name().equals(f.getAnomalyType()))
                .findFirst();

        assertTrue(rapidActOpt.isPresent(), "RAPID_POLICY_ACTIVATION finding should be detected!");
        assertEquals("HIGH", rapidActOpt.get().getSeverity());
    }

    @Test
    @DisplayName("3. REPEATED_REJECTION_PATTERN: Detects unusual concentration of rejected proposals")
    void test3_RepeatedRejectionPatternDetection() {
        // Create 3 proposals, reject all 3 (100% rejection ratio)
        for (int i = 0; i < 3; i++) {
            PolicyChangeProposal p = governanceService.createProposal(
                    new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason " + i, "Evidence"),
                    "sec-op-1"
            );
            governanceService.rejectProposal(p.getProposalId(), "sec-admin-1", "Rejection rationale " + i);
        }

        List<GovernanceSecurityFinding> findings = anomalyService.scanForAnomalies("sec-admin-1");

        Optional<GovernanceSecurityFinding> rejOpt = findings.stream()
                .filter(f -> GovernanceAnomalyType.REPEATED_REJECTION_PATTERN.name().equals(f.getAnomalyType()))
                .findFirst();

        assertTrue(rejOpt.isPresent(), "REPEATED_REJECTION_PATTERN finding should be detected!");
        assertEquals("MEDIUM", rejOpt.get().getSeverity());
    }

    @Test
    @DisplayName("4. REPEATED_APPROVAL_PATTERN: Detects high concentration of approved proposals")
    void test4_RepeatedApprovalPatternDetection() {
        // Create 4 proposals, approve all 4 (100% approval ratio)
        for (int i = 0; i < 4; i++) {
            PolicyChangeProposal p = governanceService.createProposal(
                    new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason " + i, "Evidence"),
                    "sec-op-1"
            );
            governanceService.approveProposal(p.getProposalId(), "sec-admin-1", "Approved " + i);
        }

        List<GovernanceSecurityFinding> findings = anomalyService.scanForAnomalies("sec-admin-1");

        Optional<GovernanceSecurityFinding> appOpt = findings.stream()
                .filter(f -> GovernanceAnomalyType.REPEATED_APPROVAL_PATTERN.name().equals(f.getAnomalyType()))
                .findFirst();

        assertTrue(appOpt.isPresent(), "REPEATED_APPROVAL_PATTERN finding should be detected!");
        assertEquals("MEDIUM", appOpt.get().getSeverity());
    }

    @Test
    @DisplayName("5. UNAUTHORIZED_GOVERNANCE_ATTEMPTS: Detects unauthorized governance access events in audit trail")
    void test5_UnauthorizedGovernanceAttemptsDetection() {
        // Record 2 unauthorized audit events
        auditService.recordEvent("UNAUTHORIZED_ACCESS_ATTEMPT", "corr-1", null, null, "rogue-op", "FORBIDDEN", 0, "Unauthorized approve attempt", "GOVERNANCE", "AUTH_BOUNDARY");
        auditService.recordEvent("UNAUTHORIZED_ACCESS_ATTEMPT", "corr-2", null, null, "rogue-op", "FORBIDDEN", 0, "Unauthorized activate attempt", "GOVERNANCE", "AUTH_BOUNDARY");

        List<GovernanceSecurityFinding> findings = anomalyService.scanForAnomalies("sec-admin-1");

        Optional<GovernanceSecurityFinding> unauthOpt = findings.stream()
                .filter(f -> GovernanceAnomalyType.UNAUTHORIZED_GOVERNANCE_ATTEMPTS.name().equals(f.getAnomalyType()))
                .findFirst();

        assertTrue(unauthOpt.isPresent(), "UNAUTHORIZED_GOVERNANCE_ATTEMPTS finding should be detected!");
        assertEquals("CRITICAL", unauthOpt.get().getSeverity());
    }

    @Test
    @DisplayName("6. POLICY_FLAPPING: Detects repeated threshold toggles between policy versions")
    void test6_PolicyFlappingDetection() {
        // Create version sequence with toggles: v1(50) -> v2(40) -> v3(50) -> v4(40) -> v5(50)
        int[] reviewThresholds = {40, 50, 40, 50};
        for (int i = 0; i < reviewThresholds.length; i++) {
            String type = (i % 2 == 0) ? "LOWER_REVIEW_THRESHOLD" : "RAISE_REVIEW_THRESHOLD";
            PolicyChangeProposal p = governanceService.createProposal(
                    new CreatePolicyProposalRequest(type, "Flap " + i, "Evidence", null, 80, reviewThresholds[i]),
                    "sec-op-1"
            );
            governanceService.approveProposal(p.getProposalId(), "sec-admin-1", "Approve flap");
            governanceService.activateProposal(p.getProposalId(), "sec-admin-1", "Activate flap");
        }

        List<GovernanceSecurityFinding> findings = anomalyService.scanForAnomalies("sec-admin-1");

        Optional<GovernanceSecurityFinding> flapOpt = findings.stream()
                .filter(f -> GovernanceAnomalyType.POLICY_FLAPPING.name().equals(f.getAnomalyType()))
                .findFirst();

        assertTrue(flapOpt.isPresent(), "POLICY_FLAPPING finding should be detected!");
        assertEquals("CRITICAL", flapOpt.get().getSeverity());
    }

    @Test
    @DisplayName("7. Normal baseline activity generates NO false positive anomaly findings")
    void test7_NormalActivityBaseline_NoFalsePositives() {
        // Normal baseline activity: 1 single proposal, approved and activated
        PolicyChangeProposal p = governanceService.createProposal(
                new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Normal proposal", "Evidence", null, 80, 40),
                "sec-op-1"
        );
        governanceService.approveProposal(p.getProposalId(), "sec-admin-1", "Approved");

        List<GovernanceSecurityFinding> findings = anomalyService.scanForAnomalies("sec-admin-1");

        assertTrue(findings.isEmpty(), "Normal baseline activity should not trigger any false positive findings!");
    }

    // ====================================================================
    // 2. SEVERITY & EVIDENCE GENERATION TESTS
    // ====================================================================

    @Test
    @DisplayName("8. Severity levels are assigned deterministically based on anomaly impact")
    void test8_SeverityAssignment() {
        test1_RapidGovernanceActivityDetection();

        Optional<GovernanceSecurityFinding> rapidOpt = dbFindings.stream()
                .filter(f -> GovernanceAnomalyType.RAPID_GOVERNANCE_ACTIVITY.name().equals(f.getAnomalyType()))
                .findFirst();

        assertTrue(rapidOpt.isPresent());
        assertEquals("HIGH", rapidOpt.get().getSeverity());
    }

    @Test
    @DisplayName("9. Evidence metadata is explainable and stored cleanly with findings")
    void test9_EvidenceGeneration() {
        test1_RapidGovernanceActivityDetection();

        Optional<GovernanceSecurityFinding> finding = dbFindings.stream().findFirst();
        assertTrue(finding.isPresent());
        assertNotNull(finding.get().getEvidence());
        assertTrue(finding.get().getEvidence().contains("RAPID_GOVERNANCE_ACTIVITY"));
        assertTrue(finding.get().getEvidence().contains("operator-spam"));
    }

    @Test
    @DisplayName("10. Findings are persisted correctly and retrievable via repository methods")
    void test10_FindingPersistenceAndLookup() {
        test1_RapidGovernanceActivityDetection();

        assertFalse(dbFindings.isEmpty());
        GovernanceSecurityFinding first = dbFindings.get(0);

        GovernanceSecurityFinding fetched = anomalyService.getFindingById(first.getFindingId(), "sec-admin-1");
        assertNotNull(fetched);
        assertEquals(first.getFindingId(), fetched.getFindingId());
    }

    // ====================================================================
    // 3. FINDING LIFECYCLE TESTS
    // ====================================================================

    @Test
    @DisplayName("11. Lifecycle transition OPEN -> ACKNOWLEDGED succeeds")
    void test11_FindingLifecycle_OpenToAcknowledged() {
        test1_RapidGovernanceActivityDetection();
        GovernanceSecurityFinding finding = dbFindings.get(0);
        assertEquals(GovernanceFindingStatus.OPEN.name(), finding.getStatus());

        GovernanceSecurityFinding acknowledged = anomalyService.acknowledgeFinding(finding.getFindingId(), "sec-admin-1", "Investigating rapid activity");
        assertEquals(GovernanceFindingStatus.ACKNOWLEDGED.name(), acknowledged.getStatus());
        assertEquals("sec-admin-1", acknowledged.getAcknowledgedBy());
        assertNotNull(acknowledged.getAcknowledgedAt());
    }

    @Test
    @DisplayName("12. Lifecycle transition ACKNOWLEDGED -> RESOLVED succeeds")
    void test12_FindingLifecycle_AcknowledgedToResolved() {
        test1_RapidGovernanceActivityDetection();
        GovernanceSecurityFinding finding = dbFindings.get(0);

        anomalyService.acknowledgeFinding(finding.getFindingId(), "sec-admin-1", "Acknowledged note");

        GovernanceSecurityFinding resolved = anomalyService.resolveFinding(finding.getFindingId(), "sec-admin-1", "Operator verified as authorized batch script.");
        assertEquals(GovernanceFindingStatus.RESOLVED.name(), resolved.getStatus());
        assertEquals("sec-admin-1", resolved.getResolvedBy());
        assertNotNull(resolved.getResolvedAt());
    }

    @Test
    @DisplayName("13. Invalid lifecycle transitions (RESOLVED -> OPEN / ACKNOWLEDGED) throw IllegalStateException")
    void test13_InvalidLifecycleTransition_ThrowsIllegalStateException() {
        test1_RapidGovernanceActivityDetection();
        GovernanceSecurityFinding finding = dbFindings.get(0);
        anomalyService.resolveFinding(finding.getFindingId(), "sec-admin-1", "Resolved note");

        assertThrows(IllegalStateException.class, () -> anomalyService.acknowledgeFinding(finding.getFindingId(), "sec-admin-1", "Reopen attempt"));
    }

    // ====================================================================
    // 4. AUTHORIZATION BOUNDARY TESTS
    // ====================================================================

    @Test
    @DisplayName("14. Missing X-Operator-Id header returns 403 FORBIDDEN on anomaly endpoints")
    void test14_UnauthorizedApiAccess_Returns403() {
        assertEquals(HttpStatus.FORBIDDEN, anomalyController.getAllFindings(null).getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, anomalyController.getOpenFindings(null).getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, anomalyController.getAnomalySummary(null).getStatusCode());
    }

    @Test
    @DisplayName("15. Blank X-Operator-Id header returns 403 FORBIDDEN on anomaly endpoints")
    void test15_MissingOperatorHeader_Returns403() {
        assertEquals(HttpStatus.FORBIDDEN, anomalyController.getAllFindings("   ").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, anomalyController.getOpenFindings("   ").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, anomalyController.getAnomalySummary("   ").getStatusCode());
    }

    @Test
    @DisplayName("16. ANONYMOUS operator identity returns 403 FORBIDDEN on anomaly endpoints")
    void test16_AnonymousOperator_Returns403() {
        assertEquals(HttpStatus.FORBIDDEN, anomalyController.getAllFindings("ANONYMOUS").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, anomalyController.getOpenFindings("anonymous").getStatusCode());
        assertEquals(HttpStatus.FORBIDDEN, anomalyController.getAnomalySummary("ANONYMOUS").getStatusCode());
    }

    // ====================================================================
    // 5. STRICT SECURITY INVARIANT TESTS
    // ====================================================================

    @Test
    @DisplayName("17. Zero Plaintext Security: Anomaly findings contain zero sensitive memory content or secrets")
    void test17_ZeroPlaintextProtectionInFindings() {
        test1_RapidGovernanceActivityDetection();

        List<GovernanceSecurityFinding> all = dbFindings;
        for (GovernanceSecurityFinding f : all) {
            assertFalse(f.getDescription().toLowerCase().contains("password"));
            assertFalse(f.getDescription().toLowerCase().contains("secret_key"));
            assertFalse(f.getEvidence().toLowerCase().contains("bearer_token"));
        }
    }

    @Test
    @DisplayName("18. CRITICAL INVARIANT 2: Anomaly detection scanning NEVER mutates PolicyEngine review or block thresholds")
    void test18_AnomalyDetectionDoesNotMutatePolicyEngine() {
        int reviewBefore = policyEngine.getReviewThreshold();
        int blockBefore = policyEngine.getBlockThreshold();

        anomalyService.scanForAnomalies("sec-admin-1");

        assertEquals(reviewBefore, policyEngine.getReviewThreshold());
        assertEquals(blockBefore, policyEngine.getBlockThreshold());
    }

    @Test
    @DisplayName("19. CRITICAL INVARIANT 3: Anomaly detection scanning NEVER activates policy versions or modifies proposal statuses")
    void test19_AnomalyDetectionDoesNotActivatePolicies() {
        PolicyVersion activeBefore = governanceService.getActivePolicy("sec-admin-1");

        anomalyService.scanForAnomalies("sec-admin-1");

        PolicyVersion activeAfter = governanceService.getActivePolicy("sec-admin-1");
        assertEquals(activeBefore.getVersion(), activeAfter.getVersion());
        assertEquals(activeBefore.getStatus(), activeAfter.getStatus());
    }

    @Test
    @DisplayName("20. Audit events are generated for finding detection, acknowledgment, and resolution")
    void test20_AuditEventGenerationForFindingLifecycle() {
        test1_RapidGovernanceActivityDetection();
        GovernanceSecurityFinding finding = dbFindings.get(0);

        anomalyService.acknowledgeFinding(finding.getFindingId(), "sec-admin-1", "Acknowledged note");
        anomalyService.resolveFinding(finding.getFindingId(), "sec-admin-1", "Resolved note");

        List<String> eventTypes = dbAuditEvents.stream().map(SecurityAuditEvent::getEventType).toList();
        assertTrue(eventTypes.contains("GOVERNANCE_ANOMALY_DETECTED"));
        assertTrue(eventTypes.contains("GOVERNANCE_ANOMALY_ACKNOWLEDGED"));
        assertTrue(eventTypes.contains("GOVERNANCE_ANOMALY_RESOLVED"));
    }

    @Test
    @DisplayName("21. SHA-256 audit chain integrity remains valid after anomaly audit events")
    void test21_AuditChainIntegrityRemainsValid() {
        test1_RapidGovernanceActivityDetection();
        assertTrue(auditService.verifyAuditIntegrity().isValid());
    }

    // ====================================================================
    // 6. REGRESSION TESTS (DAY 25 & DAY 26 REGRESSION CHECKS)
    // ====================================================================

    @Test
    @DisplayName("22. Day 25 Regression: Policy proposal approval and activation lifecycle functionality works properly")
    void test22_Regression_Day25GovernanceTestsPass() {
        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest("LOWER_REVIEW_THRESHOLD", "Reason", "Evidence", null, 80, 40);
        PolicyChangeProposal proposal = governanceService.createProposal(req, "sec-op-1");

        assertEquals(PolicyVersionState.PENDING_APPROVAL.name(), proposal.getStatus());

        PolicyChangeProposal approved = governanceService.approveProposal(proposal.getProposalId(), "sec-admin-1", "Approved");
        assertEquals(PolicyVersionState.APPROVED.name(), approved.getStatus());

        PolicyVersion activated = governanceService.activateProposal(approved.getProposalId(), "sec-admin-1", "Activated");
        assertEquals(PolicyVersionState.ACTIVE.name(), activated.getStatus());
        assertEquals(2, activated.getVersion());
    }

    @Test
    @DisplayName("23. Day 26 Regression: Observability summary endpoint reports anomaly statistics accurately")
    void test23_Regression_Day26ObservabilityTestsPass() {
        test1_RapidGovernanceActivityDetection();

        GovernanceAnomalySummaryResponse summary = anomalyService.getAnomalySummary("sec-admin-1");

        assertNotNull(summary);
        assertTrue(summary.getTotalFindings() > 0);
        assertTrue(summary.getOpenFindings() > 0);
        assertNotNull(summary.getBySeverity());
        assertNotNull(summary.getByAnomalyType());
    }
}

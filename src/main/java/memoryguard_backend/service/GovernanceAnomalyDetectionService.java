package memoryguard_backend.service;

import memoryguard_backend.dto.GovernanceAnomalySummaryResponse;
import memoryguard_backend.dto.GovernanceFindingResponse;
import memoryguard_backend.entity.*;
import memoryguard_backend.repository.GovernanceSecurityFindingRepository;
import memoryguard_backend.repository.PolicyChangeProposalRepository;
import memoryguard_backend.repository.PolicyVersionRepository;
import memoryguard_backend.security.PolicyEngine;
import memoryguard_backend.security.governance.anomaly.GovernanceAnomalyThresholds;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class GovernanceAnomalyDetectionService {

    private final GovernanceSecurityFindingRepository findingRepository;
    private final PolicyChangeProposalRepository proposalRepository;
    private final PolicyVersionRepository versionRepository;
    private final SecurityAuditService auditService;
    private final PolicyGovernanceService governanceService;
    private final GovernanceAnomalyThresholds thresholds;
    private final PolicyEngine policyEngine;

    private LocalDateTime lastScanTimestamp;

    @Autowired
    public GovernanceAnomalyDetectionService(
            GovernanceSecurityFindingRepository findingRepository,
            PolicyChangeProposalRepository proposalRepository,
            PolicyVersionRepository versionRepository,
            @Autowired(required = false) SecurityAuditService auditService,
            PolicyGovernanceService governanceService,
            GovernanceAnomalyThresholds thresholds,
            PolicyEngine policyEngine) {
        this.findingRepository = findingRepository;
        this.proposalRepository = proposalRepository;
        this.versionRepository = versionRepository;
        this.auditService = auditService;
        this.governanceService = governanceService;
        this.thresholds = thresholds != null ? thresholds : new GovernanceAnomalyThresholds();
        this.policyEngine = policyEngine;
    }

    /**
     * Scans for governance security anomalies using deterministic detection rules.
     * Strictly OBSERVATION + DETECTION layer. Does NOT mutate PolicyEngine or policy state.
     */
    public List<GovernanceSecurityFinding> scanForAnomalies(String operatorId) {
        governanceService.validateOperatorAuthorization(operatorId);
        this.lastScanTimestamp = LocalDateTime.now();

        List<GovernanceSecurityFinding> newFindings = new ArrayList<>();

        checkRapidGovernanceActivity(newFindings);
        checkRapidPolicyActivation(newFindings);
        checkRepeatedRejectionPattern(newFindings);
        checkRepeatedApprovalPattern(newFindings);
        checkUnauthorizedGovernanceAttempts(newFindings);
        checkPolicyFlapping(newFindings);

        return findingRepository.findAllByOrderByDetectedAtDesc();
    }

    private void checkRapidGovernanceActivity(List<GovernanceSecurityFinding> newFindings) {
        List<PolicyChangeProposal> proposals = proposalRepository.findAllByOrderByCreatedAtDesc();
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(thresholds.getWindowMinutes());

        Map<String, Long> actionCountsByOperator = new HashMap<>();

        for (PolicyChangeProposal p : proposals) {
            if ((p.getCreatedAt() == null || p.getCreatedAt().isAfter(windowStart)) && p.getCreatedBy() != null) {
                actionCountsByOperator.put(p.getCreatedBy(), actionCountsByOperator.getOrDefault(p.getCreatedBy(), 0L) + 1);
            }
            if (p.getReviewedAt() != null && p.getReviewedAt().isAfter(windowStart) && p.getReviewedBy() != null) {
                actionCountsByOperator.put(p.getReviewedBy(), actionCountsByOperator.getOrDefault(p.getReviewedBy(), 0L) + 1);
            }
        }

        for (Map.Entry<String, Long> entry : actionCountsByOperator.entrySet()) {
            String op = entry.getKey();
            long count = entry.getValue();

            if (count > thresholds.getMaxGovernanceActionsPerWindow()) {
                String anomalyType = GovernanceAnomalyType.RAPID_GOVERNANCE_ACTIVITY.name();
                if (!findingAlreadyOpenOrAcknowledged(anomalyType, op)) {
                    GovernanceSecurityFinding finding = new GovernanceSecurityFinding();
                    finding.setAnomalyType(anomalyType);
                    finding.setSeverity(GovernanceFindingSeverity.HIGH.name());
                    finding.setOperatorId(op);
                    finding.setDescription("Rapid governance activity detected for operator '" + op + "': " + count + " actions within " + thresholds.getWindowMinutes() + " minutes.");
                    finding.setEvidence(String.format("{\"anomalyType\":\"%s\",\"operatorId\":\"%s\",\"actionCount\":%d,\"windowMinutes\":%d}", anomalyType, op, count, thresholds.getWindowMinutes()));
                    finding.setStatus(GovernanceFindingStatus.OPEN.name());
                    finding.setDetectedAt(LocalDateTime.now());

                    GovernanceSecurityFinding saved = findingRepository.save(finding);
                    newFindings.add(saved);
                    emitAuditFindingEvent("GOVERNANCE_ANOMALY_DETECTED", saved);
                }
            }
        }
    }

    private void checkRapidPolicyActivation(List<GovernanceSecurityFinding> newFindings) {
        List<PolicyVersion> versions = versionRepository.findAllByOrderByVersionAsc();
        LocalDateTime windowStart = LocalDateTime.now().minusMinutes(thresholds.getWindowMinutes());

        long recentActivations = versions.stream()
                .filter(v -> (v.getActivatedAt() == null || v.getActivatedAt().isAfter(windowStart)))
                .count();

        if (recentActivations >= thresholds.getMaxPolicyActivationsPerWindow()) {
            String anomalyType = GovernanceAnomalyType.RAPID_POLICY_ACTIVATION.name();
            if (!findingAlreadyOpenOrAcknowledged(anomalyType, null)) {
                GovernanceSecurityFinding finding = new GovernanceSecurityFinding();
                finding.setAnomalyType(anomalyType);
                finding.setSeverity(GovernanceFindingSeverity.HIGH.name());
                finding.setOperatorId("MULTIPLE_OPERATORS");
                finding.setDescription("Rapid policy activations detected: " + recentActivations + " policy activations within " + thresholds.getWindowMinutes() + " minutes.");
                finding.setEvidence(String.format("{\"anomalyType\":\"%s\",\"activationCount\":%d,\"windowMinutes\":%d}", anomalyType, recentActivations, thresholds.getWindowMinutes()));
                finding.setStatus(GovernanceFindingStatus.OPEN.name());
                finding.setDetectedAt(LocalDateTime.now());

                GovernanceSecurityFinding saved = findingRepository.save(finding);
                newFindings.add(saved);
                emitAuditFindingEvent("GOVERNANCE_ANOMALY_DETECTED", saved);
            }
        }
    }

    private void checkRepeatedRejectionPattern(List<GovernanceSecurityFinding> newFindings) {
        List<PolicyChangeProposal> proposals = proposalRepository.findAllByOrderByCreatedAtDesc();
        if (proposals.size() >= 3) {
            long rejections = proposals.stream().filter(p -> PolicyVersionState.REJECTED.name().equalsIgnoreCase(p.getStatus())).count();
            double ratio = (double) rejections / proposals.size();

            if (ratio >= thresholds.getRejectionRatioThreshold()) {
                String anomalyType = GovernanceAnomalyType.REPEATED_REJECTION_PATTERN.name();
                if (!findingAlreadyOpenOrAcknowledged(anomalyType, null)) {
                    GovernanceSecurityFinding finding = new GovernanceSecurityFinding();
                    finding.setAnomalyType(anomalyType);
                    finding.setSeverity(GovernanceFindingSeverity.MEDIUM.name());
                    finding.setOperatorId("SYSTEM_GOVERNANCE");
                    finding.setDescription(String.format("Repeated proposal rejection pattern detected: %d of %d proposals rejected (%.1f%%).", rejections, proposals.size(), ratio * 100));
                    finding.setEvidence(String.format("{\"anomalyType\":\"%s\",\"rejectionCount\":%d,\"totalProposals\":%d,\"rejectionRatio\":%.2f}", anomalyType, rejections, proposals.size(), ratio));
                    finding.setStatus(GovernanceFindingStatus.OPEN.name());
                    finding.setDetectedAt(LocalDateTime.now());

                    GovernanceSecurityFinding saved = findingRepository.save(finding);
                    newFindings.add(saved);
                    emitAuditFindingEvent("GOVERNANCE_ANOMALY_DETECTED", saved);
                }
            }
        }
    }

    private void checkRepeatedApprovalPattern(List<GovernanceSecurityFinding> newFindings) {
        List<PolicyChangeProposal> proposals = proposalRepository.findAllByOrderByCreatedAtDesc();
        if (proposals.size() >= 4) {
            long approvals = proposals.stream().filter(p -> PolicyVersionState.APPROVED.name().equalsIgnoreCase(p.getStatus()) || PolicyVersionState.ACTIVE.name().equalsIgnoreCase(p.getStatus())).count();
            double ratio = (double) approvals / proposals.size();

            if (ratio >= thresholds.getApprovalRatioThreshold()) {
                String anomalyType = GovernanceAnomalyType.REPEATED_APPROVAL_PATTERN.name();
                if (!findingAlreadyOpenOrAcknowledged(anomalyType, null)) {
                    GovernanceSecurityFinding finding = new GovernanceSecurityFinding();
                    finding.setAnomalyType(anomalyType);
                    finding.setSeverity(GovernanceFindingSeverity.MEDIUM.name());
                    finding.setOperatorId("SYSTEM_GOVERNANCE");
                    finding.setDescription(String.format("Repeated proposal approval pattern detected: %d of %d proposals approved (%.1f%%).", approvals, proposals.size(), ratio * 100));
                    finding.setEvidence(String.format("{\"anomalyType\":\"%s\",\"approvalCount\":%d,\"totalProposals\":%d,\"approvalRatio\":%.2f}", anomalyType, approvals, proposals.size(), ratio));
                    finding.setStatus(GovernanceFindingStatus.OPEN.name());
                    finding.setDetectedAt(LocalDateTime.now());

                    GovernanceSecurityFinding saved = findingRepository.save(finding);
                    newFindings.add(saved);
                    emitAuditFindingEvent("GOVERNANCE_ANOMALY_DETECTED", saved);
                }
            }
        }
    }

    private void checkUnauthorizedGovernanceAttempts(List<GovernanceSecurityFinding> newFindings) {
        if (auditService != null) {
            List<SecurityAuditEvent> auditEvents = auditService.getAllEvents();
            long unauthorizedCount = auditEvents.stream()
                    .filter(e -> e.getEventType() != null && (
                            e.getEventType().contains("UNAUTHORIZED") ||
                            e.getEventType().contains("FORBIDDEN") ||
                            e.getEventType().contains("AUTH_FAILURE")
                    ))
                    .count();

            if (unauthorizedCount >= thresholds.getUnauthorizedAttemptsThreshold()) {
                String anomalyType = GovernanceAnomalyType.UNAUTHORIZED_GOVERNANCE_ATTEMPTS.name();
                if (!findingAlreadyOpenOrAcknowledged(anomalyType, null)) {
                    GovernanceSecurityFinding finding = new GovernanceSecurityFinding();
                    finding.setAnomalyType(anomalyType);
                    finding.setSeverity(GovernanceFindingSeverity.CRITICAL.name());
                    finding.setOperatorId("UNAUTHORIZED_ACTOR");
                    finding.setDescription("Unauthorized governance attempts detected: " + unauthorizedCount + " unauthorized/forbidden access attempts recorded in audit log.");
                    finding.setEvidence(String.format("{\"anomalyType\":\"%s\",\"unauthorizedCount\":%d}", anomalyType, unauthorizedCount));
                    finding.setStatus(GovernanceFindingStatus.OPEN.name());
                    finding.setDetectedAt(LocalDateTime.now());

                    GovernanceSecurityFinding saved = findingRepository.save(finding);
                    newFindings.add(saved);
                    emitAuditFindingEvent("GOVERNANCE_ANOMALY_DETECTED", saved);
                }
            }
        }
    }

    private void checkPolicyFlapping(List<GovernanceSecurityFinding> newFindings) {
        List<PolicyVersion> versions = versionRepository.findAllByOrderByVersionAsc();
        if (versions.size() >= 3) {
            int flappingSwitches = 0;
            for (int i = 2; i < versions.size(); i++) {
                PolicyVersion v1 = versions.get(i - 2);
                PolicyVersion v2 = versions.get(i - 1);
                PolicyVersion v3 = versions.get(i);

                if (v1.getReviewThreshold() == v3.getReviewThreshold() && v1.getReviewThreshold() != v2.getReviewThreshold()) {
                    flappingSwitches++;
                }
            }

            if (flappingSwitches >= thresholds.getFlappingSwitchCountThreshold()) {
                String anomalyType = GovernanceAnomalyType.POLICY_FLAPPING.name();
                if (!findingAlreadyOpenOrAcknowledged(anomalyType, null)) {
                    GovernanceSecurityFinding finding = new GovernanceSecurityFinding();
                    finding.setAnomalyType(anomalyType);
                    finding.setSeverity(GovernanceFindingSeverity.CRITICAL.name());
                    finding.setOperatorId("SYSTEM_GOVERNANCE");
                    finding.setDescription("Policy flapping detected: " + flappingSwitches + " repeated threshold toggles between policy versions.");
                    finding.setEvidence(String.format("{\"anomalyType\":\"%s\",\"versionCount\":%d,\"flappingSwitches\":%d}", anomalyType, versions.size(), flappingSwitches));
                    finding.setStatus(GovernanceFindingStatus.OPEN.name());
                    finding.setDetectedAt(LocalDateTime.now());

                    GovernanceSecurityFinding saved = findingRepository.save(finding);
                    newFindings.add(saved);
                    emitAuditFindingEvent("GOVERNANCE_ANOMALY_DETECTED", saved);
                }
            }
        }
    }

    private boolean findingAlreadyOpenOrAcknowledged(String anomalyType, String operatorId) {
        List<GovernanceSecurityFinding> existing = findingRepository.findByAnomalyType(anomalyType);
        return existing.stream().anyMatch(f -> {
            boolean activeStatus = GovernanceFindingStatus.OPEN.name().equalsIgnoreCase(f.getStatus()) ||
                    GovernanceFindingStatus.ACKNOWLEDGED.name().equalsIgnoreCase(f.getStatus());
            if (operatorId != null) {
                return activeStatus && operatorId.equalsIgnoreCase(f.getOperatorId());
            }
            return activeStatus;
        });
    }

    public List<GovernanceSecurityFinding> getAllFindings(String operatorId) {
        governanceService.validateOperatorAuthorization(operatorId);
        scanForAnomalies(operatorId);
        return findingRepository.findAllByOrderByDetectedAtDesc();
    }

    public List<GovernanceSecurityFinding> getOpenFindings(String operatorId) {
        governanceService.validateOperatorAuthorization(operatorId);
        scanForAnomalies(operatorId);
        return findingRepository.findByStatus(GovernanceFindingStatus.OPEN.name());
    }

    public GovernanceSecurityFinding getFindingById(String findingIdOrId, String operatorId) {
        governanceService.validateOperatorAuthorization(operatorId);
        return getFindingByIdInternal(findingIdOrId);
    }

    private GovernanceSecurityFinding getFindingByIdInternal(String findingIdOrId) {
        if (findingIdOrId == null || findingIdOrId.trim().isEmpty()) {
            throw new IllegalArgumentException("Finding ID cannot be null or empty");
        }

        String cleanId = findingIdOrId.trim();
        Optional<GovernanceSecurityFinding> opt = findingRepository.findByFindingId(cleanId);
        if (opt.isPresent()) {
            return opt.get();
        }

        try {
            Long numericId = Long.parseLong(cleanId);
            return findingRepository.findById(numericId)
                    .orElseThrow(() -> new IllegalArgumentException("Finding not found with ID: " + cleanId));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Finding not found with findingId: " + cleanId);
        }
    }

    public GovernanceSecurityFinding acknowledgeFinding(String findingIdOrId, String operatorId, String notes) {
        governanceService.validateAdminAuthorization(operatorId);

        GovernanceSecurityFinding finding = getFindingByIdInternal(findingIdOrId);

        GovernanceFindingStatus currentStatus = GovernanceFindingStatus.fromString(finding.getStatus());
        currentStatus.validateTransition(GovernanceFindingStatus.ACKNOWLEDGED);

        finding.setStatus(GovernanceFindingStatus.ACKNOWLEDGED.name());
        finding.setAcknowledgedBy(operatorId);
        finding.setAcknowledgedAt(LocalDateTime.now());
        if (notes != null && !notes.trim().isEmpty()) {
            finding.setResolutionNotes(notes.trim());
        }

        GovernanceSecurityFinding saved = findingRepository.save(finding);
        emitAuditFindingEvent("GOVERNANCE_ANOMALY_ACKNOWLEDGED", saved);
        return saved;
    }

    public GovernanceSecurityFinding resolveFinding(String findingIdOrId, String operatorId, String notes) {
        governanceService.validateAdminAuthorization(operatorId);

        GovernanceSecurityFinding finding = getFindingByIdInternal(findingIdOrId);

        GovernanceFindingStatus currentStatus = GovernanceFindingStatus.fromString(finding.getStatus());
        currentStatus.validateTransition(GovernanceFindingStatus.RESOLVED);

        finding.setStatus(GovernanceFindingStatus.RESOLVED.name());
        finding.setResolvedBy(operatorId);
        finding.setResolvedAt(LocalDateTime.now());
        if (notes != null && !notes.trim().isEmpty()) {
            finding.setResolutionNotes(notes.trim());
        }

        GovernanceSecurityFinding saved = findingRepository.save(finding);
        emitAuditFindingEvent("GOVERNANCE_ANOMALY_RESOLVED", saved);
        return saved;
    }

    public GovernanceAnomalySummaryResponse getAnomalySummary(String operatorId) {
        governanceService.validateOperatorAuthorization(operatorId);
        scanForAnomalies(operatorId);

        List<GovernanceSecurityFinding> all = findingRepository.findAllByOrderByDetectedAtDesc();

        long total = all.size();
        long open = all.stream().filter(f -> GovernanceFindingStatus.OPEN.name().equalsIgnoreCase(f.getStatus())).count();
        long acknowledged = all.stream().filter(f -> GovernanceFindingStatus.ACKNOWLEDGED.name().equalsIgnoreCase(f.getStatus())).count();
        long resolved = all.stream().filter(f -> GovernanceFindingStatus.RESOLVED.name().equalsIgnoreCase(f.getStatus())).count();

        Map<String, Long> bySeverity = all.stream()
                .filter(f -> f.getSeverity() != null)
                .collect(Collectors.groupingBy(GovernanceSecurityFinding::getSeverity, Collectors.counting()));

        Map<String, Long> byAnomalyType = all.stream()
                .filter(f -> f.getAnomalyType() != null)
                .collect(Collectors.groupingBy(GovernanceSecurityFinding::getAnomalyType, Collectors.counting()));

        List<GovernanceFindingResponse> recent = all.stream()
                .limit(5)
                .map(GovernanceFindingResponse::fromEntity)
                .collect(Collectors.toList());

        return new GovernanceAnomalySummaryResponse(
                total,
                open,
                acknowledged,
                resolved,
                bySeverity,
                byAnomalyType,
                recent,
                lastScanTimestamp != null ? lastScanTimestamp : LocalDateTime.now()
        );
    }

    private void emitAuditFindingEvent(String eventType, GovernanceSecurityFinding finding) {
        if (auditService != null && finding != null) {
            auditService.recordEvent(
                    eventType,
                    finding.getFindingId(),
                    null,
                    null,
                    finding.getOperatorId(),
                    finding.getStatus(),
                    0,
                    finding.getDescription(),
                    finding.getAnomalyType(),
                    "GOVERNANCE_ANOMALY_MONITORING"
            );
        }
    }
}

package memoryguard_backend.service;

import memoryguard_backend.dto.*;
import memoryguard_backend.entity.PolicyChangeProposal;
import memoryguard_backend.entity.PolicyVersion;
import memoryguard_backend.entity.PolicyVersionState;
import memoryguard_backend.entity.SecurityAuditEvent;
import memoryguard_backend.repository.PolicyChangeProposalRepository;
import memoryguard_backend.repository.PolicyVersionRepository;
import memoryguard_backend.security.PolicyEngine;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional(readOnly = true)
public class PolicyGovernanceObservabilityService {

    private final PolicyVersionRepository versionRepository;
    private final PolicyChangeProposalRepository proposalRepository;
    private final PolicyEngine policyEngine;
    private final SecurityAuditService auditService;
    private final PolicyGovernanceService governanceService;

    @Autowired
    public PolicyGovernanceObservabilityService(
            PolicyVersionRepository versionRepository,
            PolicyChangeProposalRepository proposalRepository,
            PolicyEngine policyEngine,
            @Autowired(required = false) SecurityAuditService auditService,
            PolicyGovernanceService governanceService) {
        this.versionRepository = versionRepository;
        this.proposalRepository = proposalRepository;
        this.policyEngine = policyEngine;
        this.auditService = auditService;
        this.governanceService = governanceService;
    }

    /**
     * Calculates authoritative governance metrics from persisted proposals, policy versions, and audit logs.
     * Strictly READ-ONLY and does NOT mutate PolicyEngine or policy state.
     */
    public GovernanceMetricsResponse getGovernanceMetrics(String operatorId) {
        governanceService.validateOperatorAuthorization(operatorId);

        List<PolicyChangeProposal> proposals = proposalRepository.findAllByOrderByCreatedAtDesc();
        List<PolicyVersion> versions = versionRepository.findAllByOrderByVersionAsc();

        long totalProposals = proposals.size();
        long pendingProposals = proposals.stream().filter(p -> PolicyVersionState.PENDING_APPROVAL.name().equalsIgnoreCase(p.getStatus())).count();
        long approvedProposals = proposals.stream().filter(p -> PolicyVersionState.APPROVED.name().equalsIgnoreCase(p.getStatus())).count();
        long rejectedProposals = proposals.stream().filter(p -> PolicyVersionState.REJECTED.name().equalsIgnoreCase(p.getStatus())).count();

        long activePolicyVersions = versions.stream().filter(v -> PolicyVersionState.ACTIVE.name().equalsIgnoreCase(v.getStatus())).count();
        long supersededPolicyVersions = versions.stream().filter(v -> PolicyVersionState.SUPERSEDED.name().equalsIgnoreCase(v.getStatus())).count();

        long totalPolicyActivations = activePolicyVersions + supersededPolicyVersions;
        long totalPolicyRejections = rejectedProposals;
        long totalApprovalActions = approvedProposals + proposals.stream().filter(p -> PolicyVersionState.ACTIVE.name().equalsIgnoreCase(p.getStatus())).count();
        long totalGovernanceActions = totalProposals + totalPolicyActivations + totalPolicyRejections;

        long unauthorizedGovernanceAttempts = 0;
        if (auditService != null) {
            List<SecurityAuditEvent> auditEvents = auditService.getAllEvents();
            unauthorizedGovernanceAttempts = auditEvents.stream()
                    .filter(e -> e.getEventType() != null && (
                            e.getEventType().contains("UNAUTHORIZED") ||
                            e.getEventType().contains("FORBIDDEN") ||
                            e.getEventType().contains("AUTH_FAILURE")
                    ))
                    .count();
        }

        Map<String, Long> proposalCountsByChangeType = proposals.stream()
                .filter(p -> p.getChangeType() != null)
                .collect(Collectors.groupingBy(PolicyChangeProposal::getChangeType, Collectors.counting()));

        Map<String, Long> proposalCountsByState = proposals.stream()
                .filter(p -> p.getStatus() != null)
                .collect(Collectors.groupingBy(PolicyChangeProposal::getStatus, Collectors.counting()));

        return new GovernanceMetricsResponse(
                totalProposals,
                pendingProposals,
                approvedProposals,
                rejectedProposals,
                activePolicyVersions,
                supersededPolicyVersions,
                totalPolicyActivations,
                totalPolicyRejections,
                totalApprovalActions,
                totalGovernanceActions,
                unauthorizedGovernanceAttempts,
                proposalCountsByChangeType,
                proposalCountsByState
        );
    }

    /**
     * Answers policy change history analytics questions without exposing sensitive memory content.
     * Strictly READ-ONLY and does NOT activate policies or mutate PolicyEngine.
     */
    public PolicyAnalyticsResponse getPolicyAnalytics(String operatorId) {
        governanceService.validateOperatorAuthorization(operatorId);

        PolicyVersion activeVersionEntity = governanceService.getActivePolicy(operatorId);
        List<PolicyVersion> history = governanceService.getPolicyHistory(operatorId);

        int totalPolicyVersions = history.size();
        int activatedVersionsCount = (int) history.stream().filter(v -> PolicyVersionState.ACTIVE.name().equalsIgnoreCase(v.getStatus()) || PolicyVersionState.SUPERSEDED.name().equalsIgnoreCase(v.getStatus())).count();
        int supersededVersionsCount = (int) history.stream().filter(v -> PolicyVersionState.SUPERSEDED.name().equalsIgnoreCase(v.getStatus())).count();

        PolicyVersionResponse currentActiveVersionDto = PolicyVersionResponse.fromEntity(activeVersionEntity);
        int currentReviewThreshold = activeVersionEntity.getReviewThreshold();
        int currentBlockThreshold = activeVersionEntity.getBlockThreshold();

        Integer previousReviewThreshold = null;
        Integer previousBlockThreshold = null;

        // Find the immediate previous policy version
        Optional<PolicyVersion> previousOpt = history.stream()
                .filter(v -> v.getVersion() < activeVersionEntity.getVersion())
                .max(Comparator.comparingInt(PolicyVersion::getVersion));

        if (previousOpt.isPresent()) {
            previousReviewThreshold = previousOpt.get().getReviewThreshold();
            previousBlockThreshold = previousOpt.get().getBlockThreshold();
        }

        List<PolicyVersionResponse> timeline = history.stream()
                .map(PolicyVersionResponse::fromEntity)
                .collect(Collectors.toList());

        return new PolicyAnalyticsResponse(
                totalPolicyVersions,
                activatedVersionsCount,
                supersededVersionsCount,
                currentActiveVersionDto,
                currentReviewThreshold,
                currentBlockThreshold,
                previousReviewThreshold,
                previousBlockThreshold,
                timeline
        );
    }

    /**
     * Summarizes governance activity per operator ID without exposing sensitive secrets or credentials.
     * Strictly READ-ONLY.
     */
    public List<OperatorGovernanceActivityResponse> getOperatorActivitySummary(String operatorId) {
        governanceService.validateOperatorAuthorization(operatorId);

        List<PolicyChangeProposal> proposals = proposalRepository.findAllByOrderByCreatedAtDesc();
        List<PolicyVersion> versions = versionRepository.findAllByOrderByVersionAsc();

        Set<String> operatorIds = new HashSet<>();
        for (PolicyChangeProposal p : proposals) {
            if (p.getCreatedBy() != null && !p.getCreatedBy().trim().isEmpty() && !"SYSTEM".equalsIgnoreCase(p.getCreatedBy())) {
                operatorIds.add(p.getCreatedBy().trim());
            }
            if (p.getReviewedBy() != null && !p.getReviewedBy().trim().isEmpty() && !"SYSTEM".equalsIgnoreCase(p.getReviewedBy())) {
                operatorIds.add(p.getReviewedBy().trim());
            }
        }
        for (PolicyVersion v : versions) {
            if (v.getCreatedBy() != null && !v.getCreatedBy().trim().isEmpty() && !"SYSTEM".equalsIgnoreCase(v.getCreatedBy())) {
                operatorIds.add(v.getCreatedBy().trim());
            }
            if (v.getApprovedBy() != null && !v.getApprovedBy().trim().isEmpty() && !"SYSTEM".equalsIgnoreCase(v.getApprovedBy())) {
                operatorIds.add(v.getApprovedBy().trim());
            }
            if (v.getActivatedBy() != null && !v.getActivatedBy().trim().isEmpty() && !"SYSTEM".equalsIgnoreCase(v.getActivatedBy())) {
                operatorIds.add(v.getActivatedBy().trim());
            }
        }

        List<OperatorGovernanceActivityResponse> summaries = new ArrayList<>();
        for (String op : operatorIds) {
            long created = proposals.stream().filter(p -> op.equalsIgnoreCase(p.getCreatedBy())).count();
            long approvals = proposals.stream().filter(p -> op.equalsIgnoreCase(p.getReviewedBy()) && (PolicyVersionState.APPROVED.name().equalsIgnoreCase(p.getStatus()) || PolicyVersionState.ACTIVE.name().equalsIgnoreCase(p.getStatus()))).count();
            long rejections = proposals.stream().filter(p -> op.equalsIgnoreCase(p.getReviewedBy()) && PolicyVersionState.REJECTED.name().equalsIgnoreCase(p.getStatus())).count();
            long activations = versions.stream().filter(v -> op.equalsIgnoreCase(v.getActivatedBy()) || (op.equalsIgnoreCase(v.getApprovedBy()) && PolicyVersionState.ACTIVE.name().equalsIgnoreCase(v.getStatus()))).count();
            long total = created + approvals + rejections + activations;

            summaries.add(new OperatorGovernanceActivityResponse(
                    op,
                    created,
                    approvals,
                    rejections,
                    activations,
                    total
            ));
        }

        summaries.sort(Comparator.comparing(OperatorGovernanceActivityResponse::getOperatorId));
        return summaries;
    }

    /**
     * Evaluates governance security health status. Reports issues without auto-repairing state.
     * Strictly READ-ONLY.
     */
    public GovernanceHealthResponse getGovernanceSecurityHealth(String operatorId) {
        governanceService.validateOperatorAuthorization(operatorId);

        List<PolicyVersion> activeVersions = versionRepository.findByStatus(PolicyVersionState.ACTIVE.name());
        long activeCount = activeVersions.size();
        boolean activePresent = activeCount > 0;

        List<PolicyChangeProposal> proposals = proposalRepository.findAllByOrderByCreatedAtDesc();
        long pendingCount = proposals.stream().filter(p -> PolicyVersionState.PENDING_APPROVAL.name().equalsIgnoreCase(p.getStatus())).count();
        long approvedNotActivatedCount = proposals.stream().filter(p -> PolicyVersionState.APPROVED.name().equalsIgnoreCase(p.getStatus())).count();
        long rejectedCount = proposals.stream().filter(p -> PolicyVersionState.REJECTED.name().equalsIgnoreCase(p.getStatus())).count();

        boolean auditAvailable = auditService != null;
        boolean auditIntegrityValid = auditAvailable ? auditService.verifyAuditIntegrity().isValid() : true;

        String status = "HEALTHY";
        String message = "Policy governance operating within normal security parameters.";

        if (activeCount != 1) {
            status = "UNHEALTHY";
            message = "CRITICAL SECURITY INVARIANT VIOLATION: Expected exactly 1 ACTIVE policy version, found " + activeCount + ".";
        } else if (!auditIntegrityValid) {
            status = "UNHEALTHY";
            message = "CRITICAL AUDIT INVARIANT VIOLATION: SHA-256 audit hash chain integrity failure detected.";
        } else if (approvedNotActivatedCount > 0) {
            status = "WARNING";
            message = "Governance warning: " + approvedNotActivatedCount + " approved policy proposal(s) pending activation.";
        } else if (pendingCount > 5) {
            status = "WARNING";
            message = "Governance warning: elevated pending proposal backlog (" + pendingCount + ").";
        }

        return new GovernanceHealthResponse(
                activePresent,
                activeCount,
                pendingCount,
                approvedNotActivatedCount,
                rejectedCount,
                auditAvailable,
                auditIntegrityValid,
                status,
                message
        );
    }
}

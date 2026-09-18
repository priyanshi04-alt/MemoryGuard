package memoryguard_backend.service;

import jakarta.annotation.PostConstruct;
import memoryguard_backend.dto.CalibrationRecommendation;
import memoryguard_backend.dto.CreatePolicyProposalRequest;
import memoryguard_backend.entity.PolicyChangeProposal;
import memoryguard_backend.entity.PolicyChangeType;
import memoryguard_backend.entity.PolicyVersion;
import memoryguard_backend.entity.PolicyVersionState;
import memoryguard_backend.repository.PolicyChangeProposalRepository;
import memoryguard_backend.repository.PolicyVersionRepository;
import memoryguard_backend.security.PolicyEngine;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class PolicyGovernanceService {

    private final PolicyVersionRepository versionRepository;
    private final PolicyChangeProposalRepository proposalRepository;
    private final PolicyEngine policyEngine;
    private final SecurityAuditService auditService;

    @Autowired
    public PolicyGovernanceService(
            PolicyVersionRepository versionRepository,
            PolicyChangeProposalRepository proposalRepository,
            PolicyEngine policyEngine,
            @Autowired(required = false) SecurityAuditService auditService) {
        this.versionRepository = versionRepository;
        this.proposalRepository = proposalRepository;
        this.policyEngine = policyEngine != null ? policyEngine : new PolicyEngine();
        this.auditService = auditService;
    }

    @PostConstruct
    public void init() {
        ensureInitialPolicyVersion();
    }

    /**
     * Validates operator authorization boundary for read/submit operations.
     */
    public void validateOperatorAuthorization(String operatorId) {
        if (operatorId == null || operatorId.trim().isEmpty() || "ANONYMOUS".equalsIgnoreCase(operatorId.trim())) {
            throw new SecurityException("Authorization required: valid operator identity (X-Operator-Id) must be provided.");
        }
    }

    /**
     * Validates operator authorization boundary for admin governance operations (approve, reject, activate).
     */
    public void validateAdminAuthorization(String operatorId) {
        validateOperatorAuthorization(operatorId);
        String cleaned = operatorId.trim().toLowerCase();
        if (cleaned.contains("unauthorized") || cleaned.contains("viewer") || cleaned.contains("guest") || cleaned.contains("read-only")) {
            throw new SecurityException("Forbidden: operator '" + operatorId + "' does not possess required policy-administration privileges.");
        }
    }

    /**
     * Ensures an initial active policy version (v1) exists.
     */
    @Transactional
    public synchronized PolicyVersion ensureInitialPolicyVersion() {
        Optional<PolicyVersion> activeOpt = versionRepository.findTopByStatusOrderByIdDesc(PolicyVersionState.ACTIVE.name());
        if (activeOpt.isPresent()) {
            PolicyVersion active = activeOpt.get();
            policyEngine.updateActivePolicyVersion(active);
            return active;
        }

        Optional<PolicyVersion> latestOpt = versionRepository.findTopByOrderByVersionDesc();
        if (latestOpt.isPresent()) {
            PolicyVersion latest = latestOpt.get();
            policyEngine.updateActivePolicyVersion(latest);
            return latest;
        }

        PolicyVersion v1 = new PolicyVersion();
        v1.setVersion(1);
        v1.setStatus(PolicyVersionState.ACTIVE.name());
        v1.setCreatedBy("SYSTEM");
        v1.setApprovedBy("SYSTEM");
        v1.setActivatedBy("SYSTEM");
        v1.setCreatedAt(LocalDateTime.now());
        v1.setApprovedAt(LocalDateTime.now());
        v1.setActivatedAt(LocalDateTime.now());
        v1.setReason("Initial baseline security policy");
        v1.setPreviousVersion(null);
        v1.setBlockThreshold(80);
        v1.setReviewThreshold(50);
        v1.setHighConfidenceThreshold(0.70);
        v1.setCriticalThreatAutoBlock(true);
        v1.setFailSafeDefaultDecision("REVIEW");

        PolicyVersion savedV1 = versionRepository.save(v1);
        policyEngine.updateActivePolicyVersion(savedV1);

        if (auditService != null) {
            auditService.recordEvent(
                    "POLICY_VERSION_ACTIVATED",
                    "INIT-POLICY-v1",
                    null,
                    null,
                    "SYSTEM",
                    PolicyVersionState.ACTIVE.name(),
                    50,
                    "Initial baseline policy version activated",
                    "INITIAL_BASELINE",
                    "POLICY_GOVERNANCE"
            );
        }

        return savedV1;
    }

    /**
     * Creates a persistent policy change proposal.
     */
    @Transactional
    public PolicyChangeProposal createProposal(CreatePolicyProposalRequest request, String operatorId) {
        validateOperatorAuthorization(operatorId);

        if (request == null) {
            throw new IllegalArgumentException("Proposal request payload cannot be null");
        }

        if (request.getChangeType() == null || request.getChangeType().trim().isEmpty()) {
            throw new IllegalArgumentException("Change type is required");
        }

        PolicyChangeType changeTypeEnum = PolicyChangeType.fromString(request.getChangeType());
        String changeTypeStr = changeTypeEnum.name();

        PolicyVersion activePolicy = getActivePolicy(operatorId);

        int currentReview = activePolicy.getReviewThreshold();
        int currentBlock = activePolicy.getBlockThreshold();

        int proposedReview = request.getProposedReviewThreshold() != null ? request.getProposedReviewThreshold() : currentReview;
        int proposedBlock = request.getProposedBlockThreshold() != null ? request.getProposedBlockThreshold() : currentBlock;

        if (request.getProposedReviewThreshold() == null && request.getProposedBlockThreshold() == null) {
            switch (changeTypeEnum) {
                case RAISE_REVIEW_THRESHOLD:
                    proposedReview = Math.min(currentBlock - 5, currentReview + 10);
                    break;
                case LOWER_REVIEW_THRESHOLD:
                    proposedReview = Math.max(10, currentReview - 10);
                    break;
                case REVIEW_BLOCK_RULES:
                case MAINTAIN_CURRENT_POLICY:
                    proposedReview = currentReview;
                    proposedBlock = currentBlock;
                    break;
            }
        }

        // Validate threshold ranges
        validateThresholds(proposedReview, proposedBlock);

        PolicyChangeProposal proposal = new PolicyChangeProposal();
        proposal.setRecommendationId(request.getRecommendationId());
        proposal.setCurrentPolicyVersion(activePolicy.getVersion());
        proposal.setProposedPolicyVersion(activePolicy.getVersion() + 1);
        proposal.setChangeType(changeTypeStr);
        proposal.setCurrentReviewThreshold(currentReview);
        proposal.setProposedReviewThreshold(proposedReview);
        proposal.setCurrentBlockThreshold(currentBlock);
        proposal.setProposedBlockThreshold(proposedBlock);
        proposal.setReason(request.getReason() != null ? request.getReason().trim() : "Policy change proposed by operator: " + operatorId);
        proposal.setEvidence(request.getEvidence() != null ? request.getEvidence().trim() : "Operator feedback & security telemetry proposal");
        proposal.setStatus(PolicyVersionState.PENDING_APPROVAL.name());
        proposal.setCreatedBy(operatorId);
        proposal.setCreatedAt(LocalDateTime.now());

        PolicyChangeProposal savedProposal = proposalRepository.save(proposal);

        if (auditService != null) {
            auditService.recordEvent(
                    "POLICY_CHANGE_PROPOSED",
                    savedProposal.getProposalId(),
                    null,
                    null,
                    operatorId,
                    PolicyVersionState.PENDING_APPROVAL.name(),
                    proposedReview,
                    savedProposal.getReason(),
                    changeTypeStr,
                    "POLICY_GOVERNANCE"
            );
        }

        return savedProposal;
    }

    /**
     * Converts a Day 24 calibration recommendation into a persistent policy change proposal.
     */
    @Transactional
    public PolicyChangeProposal createProposalFromRecommendation(CalibrationRecommendation recommendation, String operatorId, String customReason) {
        validateOperatorAuthorization(operatorId);

        if (recommendation == null) {
            throw new IllegalArgumentException("Recommendation cannot be null");
        }

        CreatePolicyProposalRequest req = new CreatePolicyProposalRequest(
                recommendation.getSuggestedDirection(),
                customReason != null ? customReason : recommendation.getExplanation(),
                "Calibration pattern detected: " + recommendation.getPatternDetected() + " (Confidence: " + recommendation.getConfidenceScore() + ")",
                recommendation.getPatternDetected(),
                null,
                null
        );

        return createProposal(req, operatorId);
    }

    /**
     * Gets all policy change proposals.
     */
    public List<PolicyChangeProposal> getAllProposals(String operatorId) {
        validateOperatorAuthorization(operatorId);
        return proposalRepository.findAllByOrderByCreatedAtDesc();
    }

    /**
     * Gets a single proposal by proposalId UUID or database Long ID.
     */
    public PolicyChangeProposal getProposalById(String proposalIdOrId, String operatorId) {
        validateOperatorAuthorization(operatorId);
        return getProposalByIdInternal(proposalIdOrId);
    }

    private PolicyChangeProposal getProposalByIdInternal(String proposalIdOrId) {
        if (proposalIdOrId == null || proposalIdOrId.trim().isEmpty()) {
            throw new IllegalArgumentException("Proposal ID cannot be null or empty");
        }

        String cleanId = proposalIdOrId.trim();
        Optional<PolicyChangeProposal> opt = proposalRepository.findByProposalId(cleanId);
        if (opt.isPresent()) {
            return opt.get();
        }

        try {
            Long numericId = Long.parseLong(cleanId);
            return proposalRepository.findById(numericId)
                    .orElseThrow(() -> new IllegalArgumentException("Proposal not found with ID: " + cleanId));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Proposal not found with proposalId: " + cleanId);
        }
    }

    /**
     * Approves a pending policy change proposal.
     */
    @Transactional
    public PolicyChangeProposal approveProposal(String proposalIdOrId, String operatorId, String reason) {
        validateAdminAuthorization(operatorId);

        PolicyChangeProposal proposal = getProposalByIdInternal(proposalIdOrId);

        PolicyVersionState currentState = PolicyVersionState.fromString(proposal.getStatus());
        currentState.validateTransition(PolicyVersionState.APPROVED);

        proposal.setStatus(PolicyVersionState.APPROVED.name());
        proposal.setReviewedBy(operatorId);
        proposal.setReviewedAt(LocalDateTime.now());
        if (reason != null && !reason.trim().isEmpty()) {
            proposal.setReason(proposal.getReason() + " | Approved note: " + reason.trim());
        }

        PolicyChangeProposal saved = proposalRepository.save(proposal);

        if (auditService != null) {
            auditService.recordEvent(
                    "POLICY_CHANGE_APPROVED",
                    saved.getProposalId(),
                    null,
                    null,
                    operatorId,
                    PolicyVersionState.APPROVED.name(),
                    saved.getProposedReviewThreshold(),
                    "Proposal approved by administrator: " + operatorId,
                    saved.getChangeType(),
                    "POLICY_GOVERNANCE"
            );
        }

        return saved;
    }

    /**
     * Rejects a pending policy change proposal.
     */
    @Transactional
    public PolicyChangeProposal rejectProposal(String proposalIdOrId, String operatorId, String reason) {
        validateAdminAuthorization(operatorId);

        PolicyChangeProposal proposal = getProposalByIdInternal(proposalIdOrId);

        PolicyVersionState currentState = PolicyVersionState.fromString(proposal.getStatus());
        currentState.validateTransition(PolicyVersionState.REJECTED);

        proposal.setStatus(PolicyVersionState.REJECTED.name());
        proposal.setReviewedBy(operatorId);
        proposal.setReviewedAt(LocalDateTime.now());
        if (reason != null && !reason.trim().isEmpty()) {
            proposal.setRejectionReason(reason.trim());
            proposal.setReason(proposal.getReason() + " | Rejected note: " + reason.trim());
        }

        PolicyChangeProposal saved = proposalRepository.save(proposal);

        if (auditService != null) {
            auditService.recordEvent(
                    "POLICY_CHANGE_REJECTED",
                    saved.getProposalId(),
                    null,
                    null,
                    operatorId,
                    PolicyVersionState.REJECTED.name(),
                    saved.getProposedReviewThreshold(),
                    "Proposal rejected by administrator: " + operatorId,
                    saved.getChangeType(),
                    "POLICY_GOVERNANCE"
            );
        }

        return saved;
    }

    /**
     * Activates an approved policy proposal, creating a new PolicyVersion and superseding the current active version.
     */
    @Transactional
    public PolicyVersion activateProposal(String proposalIdOrId, String operatorId, String reason) {
        validateAdminAuthorization(operatorId);

        PolicyChangeProposal proposal = getProposalByIdInternal(proposalIdOrId);

        PolicyVersionState currentState = PolicyVersionState.fromString(proposal.getStatus());
        currentState.validateTransition(PolicyVersionState.ACTIVE);

        int proposedReview = proposal.getProposedReviewThreshold() != null ? proposal.getProposedReviewThreshold() : 50;
        int proposedBlock = proposal.getProposedBlockThreshold() != null ? proposal.getProposedBlockThreshold() : 80;
        validateThresholds(proposedReview, proposedBlock);

        PolicyVersion currentActive = getActivePolicy(operatorId);

        PolicyVersionState activeState = PolicyVersionState.fromString(currentActive.getStatus());
        activeState.validateTransition(PolicyVersionState.SUPERSEDED);

        // 1. Mark current active version SUPERSEDED
        currentActive.setStatus(PolicyVersionState.SUPERSEDED.name());
        currentActive.setSupersededAt(LocalDateTime.now());
        versionRepository.save(currentActive);

        // 2. Create new active version
        PolicyVersion newVersion = new PolicyVersion();
        newVersion.setVersion(currentActive.getVersion() + 1);
        newVersion.setStatus(PolicyVersionState.ACTIVE.name());
        newVersion.setCreatedBy(proposal.getCreatedBy());
        newVersion.setApprovedBy(proposal.getReviewedBy() != null ? proposal.getReviewedBy() : operatorId);
        newVersion.setActivatedBy(operatorId);
        newVersion.setCreatedAt(proposal.getCreatedAt() != null ? proposal.getCreatedAt() : LocalDateTime.now());
        newVersion.setApprovedAt(proposal.getReviewedAt() != null ? proposal.getReviewedAt() : LocalDateTime.now());
        newVersion.setActivatedAt(LocalDateTime.now());
        newVersion.setReason("Activated proposal " + proposal.getProposalId() + ": " + (reason != null ? reason : proposal.getReason()));
        newVersion.setPreviousVersion(currentActive.getVersion());
        newVersion.setBlockThreshold(proposedBlock);
        newVersion.setReviewThreshold(proposedReview);
        newVersion.setHighConfidenceThreshold(currentActive.getHighConfidenceThreshold());
        newVersion.setCriticalThreatAutoBlock(currentActive.isCriticalThreatAutoBlock());
        newVersion.setFailSafeDefaultDecision(currentActive.getFailSafeDefaultDecision());

        PolicyVersion savedNewVersion = versionRepository.save(newVersion);

        // 3. Update proposal status to ACTIVE
        proposal.setStatus(PolicyVersionState.ACTIVE.name());
        proposal.setProposedPolicyVersion(savedNewVersion.getVersion());
        proposal.setActivatedAt(LocalDateTime.now());
        proposalRepository.save(proposal);

        // 4. Update PolicyEngine single decision authority
        policyEngine.updateActivePolicyVersion(savedNewVersion);

        // 5. Emit audit events
        if (auditService != null) {
            auditService.recordEvent(
                    "POLICY_VERSION_SUPERSEDED",
                    proposal.getProposalId(),
                    null,
                    null,
                    operatorId,
                    PolicyVersionState.SUPERSEDED.name(),
                    currentActive.getReviewThreshold(),
                    "Policy version " + currentActive.getVersion() + " superseded by version " + savedNewVersion.getVersion(),
                    proposal.getChangeType(),
                    "POLICY_GOVERNANCE"
            );

            auditService.recordEvent(
                    "POLICY_VERSION_ACTIVATED",
                    proposal.getProposalId(),
                    null,
                    null,
                    operatorId,
                    PolicyVersionState.ACTIVE.name(),
                    savedNewVersion.getReviewThreshold(),
                    "Policy version " + savedNewVersion.getVersion() + " activated by administrator: " + operatorId,
                    proposal.getChangeType(),
                    "POLICY_GOVERNANCE"
            );
        }

        return savedNewVersion;
    }

    /**
     * Gets current active policy version.
     */
    public PolicyVersion getActivePolicy(String operatorId) {
        validateOperatorAuthorization(operatorId);
        return versionRepository.findTopByStatusOrderByIdDesc(PolicyVersionState.ACTIVE.name())
                .orElseGet(this::ensureInitialPolicyVersion);
    }

    /**
     * Gets complete policy version history.
     */
    public List<PolicyVersion> getPolicyHistory(String operatorId) {
        validateOperatorAuthorization(operatorId);
        ensureInitialPolicyVersion();
        return versionRepository.findAllByOrderByVersionAsc();
    }

    private void validateThresholds(int reviewThreshold, int blockThreshold) {
        if (reviewThreshold < 0 || reviewThreshold > 100) {
            throw new IllegalArgumentException("Invalid review threshold: " + reviewThreshold + ". Must be between 0 and 100.");
        }
        if (blockThreshold < 0 || blockThreshold > 100) {
            throw new IllegalArgumentException("Invalid block threshold: " + blockThreshold + ". Must be between 0 and 100.");
        }
        if (reviewThreshold >= blockThreshold) {
            throw new IllegalArgumentException("Invalid threshold combination: review threshold (" + reviewThreshold + ") must be strictly less than block threshold (" + blockThreshold + ").");
        }
    }
}

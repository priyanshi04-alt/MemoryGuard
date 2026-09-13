package memoryguard_backend.service;

import memoryguard_backend.dto.CalibrationRecommendation;
import memoryguard_backend.dto.CalibrationResponse;
import memoryguard_backend.dto.OperatorFeedbackRequest;
import memoryguard_backend.dto.OperatorFeedbackTelemetry;
import memoryguard_backend.entity.OperatorFeedback;
import memoryguard_backend.entity.QuarantinedMemory;
import memoryguard_backend.entity.SecurityAuditEvent;
import memoryguard_backend.repository.DeniedMemoryRepository;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.repository.OperatorFeedbackRepository;
import memoryguard_backend.repository.QuarantinedMemoryRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class OperatorFeedbackService {

    public static final int MINIMUM_SAMPLE_THRESHOLD = 10;

    private final OperatorFeedbackRepository feedbackRepository;
    private final SecurityAuditService auditService;
    private final QuarantinedMemoryRepository quarantinedMemoryRepository;
    private final MemoryRepository memoryRepository;
    private final DeniedMemoryRepository deniedMemoryRepository;

    @Autowired
    public OperatorFeedbackService(
            OperatorFeedbackRepository feedbackRepository,
            SecurityAuditService auditService,
            QuarantinedMemoryRepository quarantinedMemoryRepository,
            MemoryRepository memoryRepository,
            DeniedMemoryRepository deniedMemoryRepository) {
        this.feedbackRepository = feedbackRepository;
        this.auditService = auditService;
        this.quarantinedMemoryRepository = quarantinedMemoryRepository;
        this.memoryRepository = memoryRepository;
        this.deniedMemoryRepository = deniedMemoryRepository;
    }

    /**
     * Validates operator identity authorization boundary.
     * Missing, empty, or ANONYMOUS operators are rejected.
     */
    public void validateOperatorAuthorization(String operatorId) {
        if (operatorId == null || operatorId.trim().isEmpty() || "ANONYMOUS".equalsIgnoreCase(operatorId.trim())) {
            throw new SecurityException("Authorization required: valid operator identity (X-Operator-Id) must be provided.");
        }
    }

    /**
     * Records operator feedback, integrates with SecurityAuditService, and enforces invariants.
     */
    @Transactional
    public OperatorFeedback submitFeedback(OperatorFeedbackRequest request, String headerOperatorId) {
        String effectiveOperatorId = headerOperatorId != null && !headerOperatorId.trim().isEmpty()
                ? headerOperatorId.trim()
                : (request != null ? request.getOperatorId() : null);

        validateOperatorAuthorization(effectiveOperatorId);

        if (request == null) {
            throw new IllegalArgumentException("Feedback request payload cannot be null");
        }

        if (request.getMemoryId() == null || request.getMemoryId() <= 0) {
            throw new IllegalArgumentException("Valid positive memoryId is required");
        }

        if (request.getFeedbackDecision() == null || request.getFeedbackDecision().trim().isEmpty()) {
            throw new IllegalArgumentException("Feedback decision cannot be null or empty");
        }

        String decision = request.getFeedbackDecision().trim().toUpperCase();
        if (!Set.of("APPROVED", "REJECTED", "ESCALATED").contains(decision)) {
            throw new IllegalArgumentException("Invalid feedback decision: " + decision + ". Allowed values: APPROVED, REJECTED, ESCALATED");
        }

        // Check for duplicate exact feedback
        if (feedbackRepository.existsByMemoryIdAndOperatorIdAndFeedbackDecision(request.getMemoryId(), effectiveOperatorId, decision)) {
            throw new IllegalStateException("Duplicate feedback submission: feedback decision '" + decision + "' already submitted for memory ID " + request.getMemoryId() + " by operator " + effectiveOperatorId);
        }

        OperatorFeedback feedback = new OperatorFeedback();
        feedback.setMemoryId(request.getMemoryId());
        feedback.setOperatorId(effectiveOperatorId);
        feedback.setFeedbackDecision(decision);
        feedback.setNotes(request.getNotes() != null ? request.getNotes().trim() : null);

        String corrId = request.getCorrelationId();

        // Enrich feedback record from audit timeline or repositories if available
        List<SecurityAuditEvent> events = auditService.getEventsByMemoryId(request.getMemoryId());
        if (!events.isEmpty()) {
            SecurityAuditEvent primaryEvent = events.stream()
                    .filter(e -> "MEMORY_PERMITTED".equals(e.getEventType()) ||
                            "MEMORY_QUARANTINED".equals(e.getEventType()) ||
                            "MEMORY_DENIED".equals(e.getEventType()))
                    .findFirst()
                    .orElse(events.get(0));

            if (corrId == null || corrId.trim().isEmpty()) {
                corrId = primaryEvent.getCorrelationId();
            }
            feedback.setPolicyDecision(primaryEvent.getPolicyDecision());
            feedback.setRiskScore(primaryEvent.getRiskScore());
            feedback.setPolicyReason(primaryEvent.getPolicyRule());
            feedback.setContributingFactors(primaryEvent.getContributingFactors());

            if (primaryEvent.getRiskScore() != null) {
                feedback.setRiskLevel(primaryEvent.getRiskScore() >= 80 ? "HIGH" :
                        (primaryEvent.getRiskScore() >= 50 ? "MEDIUM" : "LOW"));
            }
        } else {
            // Check QuarantinedMemory if no audit events found
            if (quarantinedMemoryRepository != null) {
                Optional<QuarantinedMemory> qmOpt = quarantinedMemoryRepository.findById(request.getMemoryId());
                if (qmOpt.isPresent()) {
                    QuarantinedMemory qm = qmOpt.get();
                    if (corrId == null) corrId = qm.getCorrelationId();
                    feedback.setPolicyDecision("REVIEW");
                    feedback.setRiskScore(qm.getRiskScore());
                    feedback.setRiskLevel(qm.getRiskLevel());
                    feedback.setPolicyReason(qm.getPolicyRule());
                    feedback.setContributingFactors(qm.getContributingFactors());
                }
            }
        }

        feedback.setCorrelationId(corrId);
        if (feedback.getPolicyDecision() == null) {
            feedback.setPolicyDecision("REVIEW");
        }
        if (feedback.getRiskLevel() == null) {
            feedback.setRiskLevel("MEDIUM");
        }

        OperatorFeedback savedFeedback = feedbackRepository.save(feedback);

        // Integrate with Day 23 audit trail
        auditService.recordEvent(
                "OPERATOR_FEEDBACK_SUBMITTED",
                corrId,
                feedback.getMemoryId(),
                null,
                effectiveOperatorId,
                decision,
                feedback.getRiskScore() != null ? feedback.getRiskScore() : 0,
                "FEEDBACK:" + decision + (feedback.getNotes() != null ? " | " + feedback.getNotes() : ""),
                feedback.getPolicyReason() != null ? feedback.getPolicyReason() : "OPERATOR_FEEDBACK",
                "OPERATOR_FEEDBACK_LOOP"
        );

        return savedFeedback;
    }

    /**
     * Gets feedback by memory ID with operator authorization check.
     */
    public List<OperatorFeedback> getFeedbackByMemoryId(Long memoryId, String operatorId) {
        validateOperatorAuthorization(operatorId);
        if (memoryId == null || memoryId <= 0) {
            throw new IllegalArgumentException("Valid positive memoryId is required");
        }
        return feedbackRepository.findByMemoryIdOrderByTimestampAsc(memoryId);
    }

    /**
     * Builds structured security telemetry from stored operator feedback.
     */
    public OperatorFeedbackTelemetry getTelemetry(String operatorId) {
        validateOperatorAuthorization(operatorId);

        List<OperatorFeedback> allFeedback = feedbackRepository.findAllByOrderByIdAsc();
        OperatorFeedbackTelemetry telemetry = new OperatorFeedbackTelemetry();

        telemetry.setTotalFeedbackCount(allFeedback.size());

        if (allFeedback.isEmpty()) {
            return telemetry;
        }

        long approvedCount = allFeedback.stream().filter(f -> "APPROVED".equalsIgnoreCase(f.getFeedbackDecision())).count();
        long rejectedCount = allFeedback.stream().filter(f -> "REJECTED".equalsIgnoreCase(f.getFeedbackDecision())).count();
        long escalatedCount = allFeedback.stream().filter(f -> "ESCALATED".equalsIgnoreCase(f.getFeedbackDecision())).count();

        telemetry.setApprovedCount(approvedCount);
        telemetry.setRejectedCount(rejectedCount);
        telemetry.setEscalatedCount(escalatedCount);

        Map<String, Long> dist = new HashMap<>();
        dist.put("APPROVED", approvedCount);
        dist.put("REJECTED", rejectedCount);
        dist.put("ESCALATED", escalatedCount);
        telemetry.setFeedbackDistribution(dist);

        long reviewApproved = allFeedback.stream()
                .filter(f -> "REVIEW".equalsIgnoreCase(f.getPolicyDecision()) && "APPROVED".equalsIgnoreCase(f.getFeedbackDecision()))
                .count();

        long reviewRejected = allFeedback.stream()
                .filter(f -> "REVIEW".equalsIgnoreCase(f.getPolicyDecision()) && "REJECTED".equalsIgnoreCase(f.getFeedbackDecision()))
                .count();

        long reviewEscalated = allFeedback.stream()
                .filter(f -> "REVIEW".equalsIgnoreCase(f.getPolicyDecision()) && "ESCALATED".equalsIgnoreCase(f.getFeedbackDecision()))
                .count();

        long blockEscalated = allFeedback.stream()
                .filter(f -> "BLOCK".equalsIgnoreCase(f.getPolicyDecision()) && "ESCALATED".equalsIgnoreCase(f.getFeedbackDecision()))
                .count();

        telemetry.setReviewApprovedCount(reviewApproved);
        telemetry.setReviewRejectedCount(reviewRejected);
        telemetry.setReviewEscalatedCount(reviewEscalated);
        telemetry.setBlockEscalatedCount(blockEscalated);

        long overrides = reviewApproved + reviewRejected + blockEscalated;
        double overrideRate = (double) overrides / allFeedback.size();
        telemetry.setOverrideRate(overrideRate);

        // Disagreements by risk level
        Map<String, Long> riskDisagreements = new HashMap<>();
        for (OperatorFeedback f : allFeedback) {
            if (isDisagreement(f)) {
                String rLevel = f.getRiskLevel() != null ? f.getRiskLevel() : "UNKNOWN";
                riskDisagreements.put(rLevel, riskDisagreements.getOrDefault(rLevel, 0L) + 1);
            }
        }
        telemetry.setRiskLevelDisagreements(riskDisagreements);

        // Disagreements by signal
        Map<String, Long> signalDisagreements = new HashMap<>();
        for (OperatorFeedback f : allFeedback) {
            if (isDisagreement(f) && f.getContributingFactors() != null) {
                String[] factors = f.getContributingFactors().split("\\s*\\|\\s*");
                for (String factor : factors) {
                    if (!factor.trim().isEmpty() && !factor.startsWith("FEEDBACK:")) {
                        signalDisagreements.put(factor.trim(), signalDisagreements.getOrDefault(factor.trim(), 0L) + 1);
                    }
                }
            }
        }
        telemetry.setSignalDisagreements(signalDisagreements);

        return telemetry;
    }

    /**
     * Generates controlled calibration recommendations when minimum sample threshold is met.
     */
    public CalibrationResponse getCalibrationRecommendations(String operatorId) {
        validateOperatorAuthorization(operatorId);

        List<OperatorFeedback> allFeedback = feedbackRepository.findAllByOrderByIdAsc();
        long totalObs = allFeedback.size();

        if (totalObs < MINIMUM_SAMPLE_THRESHOLD) {
            return new CalibrationResponse(
                    MINIMUM_SAMPLE_THRESHOLD,
                    totalObs,
                    false,
                    "INSUFFICIENT_DATA",
                    List.of()
            );
        }

        List<CalibrationRecommendation> recommendations = new ArrayList<>();

        long reviewTotal = allFeedback.stream().filter(f -> "REVIEW".equalsIgnoreCase(f.getPolicyDecision())).count();
        long reviewApproved = allFeedback.stream()
                .filter(f -> "REVIEW".equalsIgnoreCase(f.getPolicyDecision()) && "APPROVED".equalsIgnoreCase(f.getFeedbackDecision()))
                .count();
        long reviewRejected = allFeedback.stream()
                .filter(f -> "REVIEW".equalsIgnoreCase(f.getPolicyDecision()) && "REJECTED".equalsIgnoreCase(f.getFeedbackDecision()))
                .count();
        long blockEscalated = allFeedback.stream()
                .filter(f -> "BLOCK".equalsIgnoreCase(f.getPolicyDecision()) && "ESCALATED".equalsIgnoreCase(f.getFeedbackDecision()))
                .count();

        if (reviewTotal > 0 && ((double) reviewApproved / reviewTotal) >= 0.40) {
            double conf = (double) reviewApproved / reviewTotal;
            recommendations.add(new CalibrationRecommendation(
                    "HIGH_REVIEW_APPROVAL_RATE",
                    reviewApproved,
                    "MEDIUM_RISK_REVIEW",
                    Math.round(conf * 100.0) / 100.0,
                    "RAISE_REVIEW_THRESHOLD",
                    "Operators approved " + reviewApproved + " out of " + reviewTotal + " REVIEW decisions (" + String.format("%.0f", conf * 100) + "%). Suggest raising REVIEW threshold or reducing sensitivity to avoid false positive quarantines."
            ));
        }

        if (reviewTotal > 0 && ((double) reviewRejected / reviewTotal) >= 0.40) {
            double conf = (double) reviewRejected / reviewTotal;
            recommendations.add(new CalibrationRecommendation(
                    "HIGH_REVIEW_REJECTION_RATE",
                    reviewRejected,
                    "MEDIUM_RISK_REVIEW",
                    Math.round(conf * 100.0) / 100.0,
                    "LOWER_REVIEW_THRESHOLD",
                    "Operators rejected " + reviewRejected + " out of " + reviewTotal + " REVIEW decisions (" + String.format("%.0f", conf * 100) + "%). Suggest lowering REVIEW threshold to catch malicious memories earlier."
            ));
        }

        if (blockEscalated >= 2) {
            double conf = Math.min(1.0, blockEscalated / 5.0);
            recommendations.add(new CalibrationRecommendation(
                    "FREQUENT_BLOCK_ESCALATION",
                    blockEscalated,
                    "HIGH_RISK_BLOCK",
                    Math.round(conf * 100.0) / 100.0,
                    "REVIEW_BLOCK_RULES",
                    "Operators escalated " + blockEscalated + " BLOCKED decisions for secondary investigation. Recommend auditing BLOCK policy rules for false positives."
            ));
        }

        if (recommendations.isEmpty()) {
            recommendations.add(new CalibrationRecommendation(
                    "BALANCED_OPERATOR_ALIGNMENT",
                    totalObs,
                    "BASELINE_POLICY",
                    1.0,
                    "MAINTAIN_CURRENT_POLICY",
                    "Operator feedback aligns within expected parameters. Current PolicyEngine thresholds require no adjustment."
            ));
        }

        return new CalibrationResponse(
                MINIMUM_SAMPLE_THRESHOLD,
                totalObs,
                true,
                "SUFFICIENT_DATA",
                recommendations
        );
    }

    private boolean isDisagreement(OperatorFeedback f) {
        if (f == null || f.getPolicyDecision() == null || f.getFeedbackDecision() == null) return false;
        String pDec = f.getPolicyDecision().toUpperCase();
        String fDec = f.getFeedbackDecision().toUpperCase();

        if ("REVIEW".equals(pDec) && ("APPROVED".equals(fDec) || "REJECTED".equals(fDec))) {
            return true;
        }
        if ("BLOCK".equals(pDec) && "ESCALATED".equals(fDec)) {
            return true;
        }
        if ("ALLOW".equals(pDec) && ("REJECTED".equals(fDec) || "ESCALATED".equals(fDec))) {
            return true;
        }
        return false;
    }
}

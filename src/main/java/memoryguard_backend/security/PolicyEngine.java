package memoryguard_backend.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Context-aware Policy Engine for MemoryGuard.
 * Separates security policy decision-making from detection and risk aggregation.
 * Interprets multi-layer security evidence, risk scores, confidence, and signals
 * to make explainable final memory security decisions: ALLOW, REVIEW, or BLOCK.
 */
@Component
public class PolicyEngine {

    private final PolicyProperties policyProperties;

    @Autowired
    public PolicyEngine(PolicyProperties policyProperties) {
        this.policyProperties = policyProperties != null ? policyProperties : new PolicyProperties();
    }

    public PolicyEngine() {
        this.policyProperties = new PolicyProperties();
    }

    /**
     * Legacy helper method for single-score threshold checks.
     */
    public PolicyDecision decide(int riskScore) {
        if (riskScore >= policyProperties.getBlockThreshold()) {
            return PolicyDecision.BLOCK;
        }

        if (riskScore >= policyProperties.getReviewThreshold()) {
            return PolicyDecision.REVIEW;
        }

        return PolicyDecision.ALLOW;
    }

    /**
     * Evaluates multi-dimensional security evidence using deterministic policy priority order.
     */
    public PolicyDecisionResult evaluate(AggregatedRiskAssessment assessment) {

        // ====================================================================
        // RULE 1: FAIL_SAFE_MISSING_ANALYSIS
        // Missing, null, unperformed, or invalid risk assessment -> Safe Fallback (REVIEW)
        // ====================================================================
        if (assessment == null || "NO_ANALYSIS".equalsIgnoreCase(assessment.getPrimaryCategory())) {
            String fallbackDecisionStr = policyProperties.getFailSafeDefaultDecision();
            PolicyDecision fallbackDecision = "BLOCK".equalsIgnoreCase(fallbackDecisionStr) ? PolicyDecision.BLOCK : PolicyDecision.REVIEW;
            String persistenceStatus = fallbackDecision == PolicyDecision.BLOCK ? "DENIED" : "QUARANTINED";
            
            return new PolicyDecisionResult(
                    fallbackDecision,
                    60,
                    "MEDIUM",
                    0.0,
                    "FAIL_SAFE_MISSING_ANALYSIS",
                    "Security analysis unavailable or incomplete; routing to REVIEW for safety (fail-safe policy).",
                    List.of("ANALYSIS_MISSING_OR_FAILED"),
                    persistenceStatus
            );
        }

        int score = Math.min(100, Math.max(0, assessment.getOverallRiskScore()));
        double confidence = Math.min(1.0, Math.max(0.0, assessment.getConfidence()));
        String category = assessment.getPrimaryCategory() != null ? assessment.getPrimaryCategory() : "UNKNOWN";
        String riskLevel = assessment.getOverallRiskLevel() != null ? assessment.getOverallRiskLevel() : deriveRiskLevel(score);
        String primaryReason = assessment.getPrimaryReason() != null ? assessment.getPrimaryReason() : "";
        List<String> contributingFactors = new ArrayList<>(assessment.getDetectedSignals());

        boolean hasCriticalThreat = isCriticalSignal(category, contributingFactors);
        boolean hasBehavioralManipulation = isBehavioralManipulation(category, contributingFactors);
        boolean hasBenignContent = isBenignContent(category, contributingFactors);
        boolean isHighConfidence = confidence >= policyProperties.getHighConfidenceThreshold();

        // ====================================================================
        // RULE 2: CRITICAL_HIGH_CONFIDENCE_THREAT
        // High-impact critical threat + score >= blockThreshold + high confidence -> BLOCK
        // ====================================================================
        if (policyProperties.isCriticalThreatAutoBlock() && hasCriticalThreat && score >= policyProperties.getBlockThreshold() && isHighConfidence) {
            String explanation = "Memory automatically BLOCKED because it contains a critical threat indicator (" + category + "). " + primaryReason;
            return new PolicyDecisionResult(
                    PolicyDecision.BLOCK,
                    score,
                    riskLevel,
                    confidence,
                    "CRITICAL_HIGH_CONFIDENCE_THREAT",
                    explanation,
                    contributingFactors,
                    "DENIED"
            );
        }

        // ====================================================================
        // RULE 3: AMBIGUOUS_HIGH_RISK
        // High risk score (>= blockThreshold) BUT low confidence (< highConfidenceThreshold) -> REVIEW
        // Preserves: Risk != Certainty
        // ====================================================================
        if (score >= policyProperties.getBlockThreshold() && !isHighConfidence) {
            String explanation = "Memory flagged for REVIEW: high risk score (" + score + "/100) detected, but confidence (" + String.format("%.2f", confidence) + ") is insufficient for automatic blocking. " + primaryReason;
            return new PolicyDecisionResult(
                    PolicyDecision.REVIEW,
                    score,
                    riskLevel,
                    confidence,
                    "AMBIGUOUS_HIGH_RISK",
                    explanation,
                    contributingFactors,
                    "QUARANTINED"
            );
        }

        // ====================================================================
        // RULE 4: BENIGN_EDUCATIONAL_CONTENT
        // Educational/non-actionable security discussion without malicious signals -> ALLOW
        // ====================================================================
        if (hasBenignContent && !hasCriticalThreat && score < policyProperties.getReviewThreshold()) {
            String explanation = "Memory ALLOWED: educational or benign security content detected without actionable threat context. " + primaryReason;
            return new PolicyDecisionResult(
                    PolicyDecision.ALLOW,
                    score,
                    "LOW",
                    confidence,
                    "BENIGN_EDUCATIONAL_CONTENT",
                    explanation,
                    contributingFactors,
                    "PERMITTED"
            );
        }

        // ====================================================================
        // RULE 5: BEHAVIORAL_MANIPULATION_REVIEW / BLOCK
        // Intent to alter future behavior (instructions, tools, context) -> REVIEW or BLOCK
        // ====================================================================
        if (hasBehavioralManipulation && score >= policyProperties.getReviewThreshold()) {
            if (score >= policyProperties.getBlockThreshold() && isHighConfidence) {
                String explanation = "Memory BLOCKED: direct instruction override or persistence manipulation attempt detected with high confidence. " + primaryReason;
                return new PolicyDecisionResult(
                        PolicyDecision.BLOCK,
                        score,
                        riskLevel,
                        confidence,
                        "BEHAVIORAL_MANIPULATION_BLOCK",
                        explanation,
                        contributingFactors,
                        "DENIED"
                );
            } else {
                String explanation = "Memory flagged for REVIEW: content attempts to manipulate future agent behavior, context, or tool execution. " + primaryReason;
                return new PolicyDecisionResult(
                        PolicyDecision.REVIEW,
                        score,
                        riskLevel,
                        confidence,
                        "BEHAVIORAL_MANIPULATION_REVIEW",
                        explanation,
                        contributingFactors,
                        "QUARANTINED"
                );
            }
        }

        // ====================================================================
        // RULE 6: SCORE_THRESHOLD_BLOCK
        // High Risk Score Threshold (>= blockThreshold) with adequate confidence -> BLOCK
        // ====================================================================
        if (score >= policyProperties.getBlockThreshold()) {
            String explanation = "Memory BLOCKED due to high overall risk score (" + score + "/100). " + primaryReason;
            return new PolicyDecisionResult(
                    PolicyDecision.BLOCK,
                    score,
                    riskLevel,
                    confidence,
                    "SCORE_THRESHOLD_BLOCK",
                    explanation,
                    contributingFactors,
                    "DENIED"
            );
        }

        // ====================================================================
        // RULE 7: SCORE_THRESHOLD_REVIEW
        // Medium Risk Score Threshold (>= reviewThreshold) -> REVIEW
        // ====================================================================
        if (score >= policyProperties.getReviewThreshold()) {
            String explanation = "Memory flagged for REVIEW due to moderate risk score (" + score + "/100) or ambiguous security context. " + primaryReason;
            return new PolicyDecisionResult(
                    PolicyDecision.REVIEW,
                    score,
                    riskLevel,
                    confidence,
                    "SCORE_THRESHOLD_REVIEW",
                    explanation,
                    contributingFactors,
                    "QUARANTINED"
            );
        }

        // ====================================================================
        // RULE 8: LOW_RISK_BASELINE
        // Low Risk Baseline -> ALLOW
        // ====================================================================
        String explanation = "Memory ALLOWED: content evaluated as low risk (" + score + "/100) with verified trust baseline.";
        return new PolicyDecisionResult(
                PolicyDecision.ALLOW,
                score,
                "LOW",
                confidence,
                "LOW_RISK_BASELINE",
                explanation,
                contributingFactors,
                "PERMITTED"
        );
    }

    private boolean isCriticalSignal(String category, List<String> signals) {
        if (category != null) {
            String catUpper = category.toUpperCase();
            if (catUpper.contains("PROMPT_INJECTION") ||
                catUpper.contains("SECRET_EXFILTRATION") ||
                catUpper.contains("CREDENTIAL_EXPOSURE") ||
                catUpper.contains("PRIVILEGE_ESCALATION") ||
                catUpper.contains("TOOL_MANIPULATION") ||
                catUpper.contains("MALICIOUS_PERSISTENCE") ||
                catUpper.contains("INSTRUCTION_OVERRIDE")) {
                return true;
            }
        }
        if (signals != null) {
            for (String sig : signals) {
                String sigUpper = sig.toUpperCase();
                if (sigUpper.contains("PROMPT_INJECTION") ||
                    sigUpper.contains("SECRET_EXFILTRATION") ||
                    sigUpper.contains("CREDENTIAL_EXPOSURE") ||
                    sigUpper.contains("PRIVILEGE_ESCALATION") ||
                    sigUpper.contains("TOOL_MANIPULATION") ||
                    sigUpper.contains("MALICIOUS_PERSISTENCE") ||
                    sigUpper.contains("INSTRUCTION_OVERRIDE")) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isBehavioralManipulation(String category, List<String> signals) {
        if (category != null) {
            String catUpper = category.toUpperCase();
            if (catUpper.contains("INSTRUCTION_OVERRIDE") ||
                catUpper.contains("MALICIOUS_PERSISTENCE") ||
                catUpper.contains("SUSPICIOUS_INSTRUCTION") ||
                catUpper.contains("SOCIAL_ENGINEERING") ||
                catUpper.contains("CONTEXT_MANIPULATION") ||
                catUpper.contains("TOOL_MANIPULATION")) {
                return true;
            }
        }
        if (signals != null) {
            for (String sig : signals) {
                String sigUpper = sig.toUpperCase();
                if (sigUpper.contains("INSTRUCTION_OVERRIDE") ||
                    sigUpper.contains("MALICIOUS_PERSISTENCE") ||
                    sigUpper.contains("SUSPICIOUS_INSTRUCTION") ||
                    sigUpper.contains("SOCIAL_ENGINEERING") ||
                    sigUpper.contains("CONTEXT_MANIPULATION") ||
                    sigUpper.contains("TOOL_MANIPULATION")) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isBenignContent(String category, List<String> signals) {
        if (category != null && category.toUpperCase().contains("BENIGN_SECURITY_CONTENT")) {
            return true;
        }
        if (signals != null) {
            for (String sig : signals) {
                if (sig.toUpperCase().contains("BENIGN_SECURITY_CONTENT")) {
                    return true;
                }
            }
        }
        return false;
    }

    private String deriveRiskLevel(int score) {
        if (score >= 80) return "HIGH";
        if (score >= 50) return "MEDIUM";
        return "LOW";
    }
}
package memoryguard_backend.security.explainability;

import memoryguard_backend.entity.DeniedMemoryRecord;
import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.ProvenanceType;
import memoryguard_backend.entity.QuarantinedMemory;
import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.security.*;
import memoryguard_backend.security.context.ContextAnalysisResult;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;

/**
 * Security Decision Explanation Engine for MemoryGuard.
 * CORE PRINCIPLE: PolicyEngine decides. ExplanationEngine explains.
 * The explanation engine MUST NEVER independently decide ALLOW, REVIEW, or BLOCK.
 */
@Component
public class ExplanationEngine {

    /**
     * Generates a structured, explainable security decision explanation from pre-computed PolicyDecisionResult
     * and aggregated risk assessment evidence.
     */
    public SecurityDecisionExplanation explain(
            Long memoryId,
            String correlationId,
            PolicyDecisionResult policyResult,
            AggregatedRiskAssessment riskAssessment,
            Memory memory,
            ProvenanceAnalysisResult provenanceResult,
            ContextAnalysisResult contextResult) {

        if (policyResult == null) {
            throw new IllegalArgumentException("PolicyDecisionResult cannot be null for explanation generation");
        }

        PolicyDecision finalDecision = policyResult.getDecision();
        int score = policyResult.getRiskScore();
        String riskLevel = policyResult.getRiskLevel();
        double confidence = policyResult.getConfidence();
        String policyRule = policyResult.getPolicyRule();

        String resolvedCorrelationId = correlationId != null && !correlationId.isEmpty() ? correlationId :
                (memory != null && memory.getCorrelationId() != null ? memory.getCorrelationId() : UUID.randomUUID().toString());

        // Extract Threat Categories
        List<ThreatCategory> threatCategories = extractThreatCategories(policyResult, riskAssessment, memory, provenanceResult, contextResult);

        // Extract Contributing Factors
        List<ContributingFactor> contributingFactors = extractContributingFactors(policyResult, riskAssessment, memory, provenanceResult, contextResult);

        // Extract Analyzer Findings
        List<String> analyzerFindings = extractAnalyzerFindings(policyResult, riskAssessment, memory, provenanceResult, contextResult);

        // Build Evidence Chain
        EvidenceChain evidenceChain = buildEvidenceChain(policyResult, riskAssessment, memory, provenanceResult, contextResult);

        // Generate Deterministic Summary
        String summary = generateDeterministicSummary(finalDecision, policyResult, riskAssessment, threatCategories, contributingFactors);

        SecurityDecisionExplanation explanation = new SecurityDecisionExplanation(
                memoryId,
                resolvedCorrelationId,
                finalDecision,
                score,
                riskLevel,
                confidence,
                policyRule,
                threatCategories,
                contributingFactors,
                analyzerFindings,
                evidenceChain,
                summary,
                LocalDateTime.now()
        );

        // ENFORCE CRITICAL INVARIANT: Explanation.finalDecision MUST equal PolicyDecisionResult.finalDecision
        verifyDecisionConsistencyInvariant(explanation, policyResult);

        return explanation;
    }

    /**
     * Overload for constructing explanation from persisted SecurityLog record.
     */
    public SecurityDecisionExplanation explainFromSecurityLog(SecurityLog log) {
        if (log == null) {
            throw new IllegalArgumentException("SecurityLog record cannot be null");
        }

        PolicyDecision decision = parseDecisionFromAction(log.getActionTaken());
        PolicyDecisionResult policyResult = new PolicyDecisionResult(
                decision,
                log.getRiskScore(),
                log.getRiskLevel() != null ? log.getRiskLevel() : "MEDIUM",
                log.getConfidence() != null ? log.getConfidence() : 0.9,
                log.getThreatType() != null ? log.getThreatType() : "POLICY_RULE",
                log.getExplanation() != null ? log.getExplanation() : "",
                log.getContributingSignals() != null ? Arrays.asList(log.getContributingSignals().split("\\s*\\|\\s*")) : List.of(),
                log.getActionTaken()
        );

        List<ThreatCategory> categories = parseThreatCategoriesFromLog(log);
        List<ContributingFactor> factors = parseContributingFactorsFromLog(log, categories);
        List<String> findings = policyResult.getContributingFactors();
        EvidenceChain chain = buildEvidenceChainFromLog(log, policyResult);

        String summary = log.getExplanation() != null && !log.getExplanation().isEmpty() ? log.getExplanation() :
                generateDeterministicSummary(decision, policyResult, null, categories, factors);

        SecurityDecisionExplanation explanation = new SecurityDecisionExplanation(
                log.getMemoryId(),
                log.getCorrelationId(),
                decision,
                log.getRiskScore(),
                log.getRiskLevel() != null ? log.getRiskLevel() : "MEDIUM",
                log.getConfidence() != null ? log.getConfidence() : 0.9,
                log.getThreatType() != null ? log.getThreatType() : "POLICY_RULE",
                categories,
                factors,
                findings,
                chain,
                summary,
                log.getCreatedAt() != null ? log.getCreatedAt() : LocalDateTime.now()
        );

        verifyDecisionConsistencyInvariant(explanation, policyResult);
        return explanation;
    }

    /**
     * Overload for constructing explanation from QuarantinedMemory item.
     */
    public SecurityDecisionExplanation explainFromQuarantinedMemory(QuarantinedMemory qm) {
        if (qm == null) {
            throw new IllegalArgumentException("QuarantinedMemory record cannot be null");
        }

        PolicyDecisionResult policyResult = new PolicyDecisionResult(
                PolicyDecision.REVIEW,
                qm.getRiskScore(),
                qm.getRiskLevel() != null ? qm.getRiskLevel() : "MEDIUM",
                qm.getConfidence(),
                qm.getPolicyRule() != null ? qm.getPolicyRule() : "SCORE_THRESHOLD_REVIEW",
                qm.getExplanation(),
                qm.getContributingFactors() != null ? Arrays.asList(qm.getContributingFactors().split("\\s*\\|\\s*")) : List.of(),
                "QUARANTINED"
        );

        List<ThreatCategory> categories = deriveCategoriesFromRuleAndSignals(qm.getPolicyRule(), qm.getContributingFactors(), qm.getProvenance() != null ? qm.getProvenance().name() : null);
        List<ContributingFactor> factors = deriveFactorsFromSignals(qm.getContributingFactors(), categories);
        List<String> findings = policyResult.getContributingFactors();

        EvidenceChain chain = buildEvidenceChainFromQuarantinedMemory(qm, policyResult);
        String summary = generateDeterministicSummary(PolicyDecision.REVIEW, policyResult, null, categories, factors);

        SecurityDecisionExplanation explanation = new SecurityDecisionExplanation(
                qm.getId(),
                qm.getCorrelationId(),
                PolicyDecision.REVIEW,
                qm.getRiskScore(),
                qm.getRiskLevel() != null ? qm.getRiskLevel() : "MEDIUM",
                qm.getConfidence(),
                qm.getPolicyRule() != null ? qm.getPolicyRule() : "SCORE_THRESHOLD_REVIEW",
                categories,
                factors,
                findings,
                chain,
                summary,
                qm.getCreatedAt() != null ? qm.getCreatedAt() : LocalDateTime.now()
        );

        verifyDecisionConsistencyInvariant(explanation, policyResult);
        return explanation;
    }

    /**
     * Overload for constructing explanation from DeniedMemoryRecord item (Zero Plaintext Leak Guaranteed).
     */
    public SecurityDecisionExplanation explainFromDeniedRecord(DeniedMemoryRecord dmr) {
        if (dmr == null) {
            throw new IllegalArgumentException("DeniedMemoryRecord cannot be null");
        }

        PolicyDecisionResult policyResult = new PolicyDecisionResult(
                PolicyDecision.BLOCK,
                dmr.getRiskScore(),
                dmr.getRiskLevel() != null ? dmr.getRiskLevel() : "HIGH",
                dmr.getConfidence(),
                dmr.getPolicyRule() != null ? dmr.getPolicyRule() : "SCORE_THRESHOLD_BLOCK",
                dmr.getExplanation(),
                dmr.getContributingFactors() != null ? Arrays.asList(dmr.getContributingFactors().split("\\s*\\|\\s*")) : List.of(),
                "DENIED"
        );

        List<ThreatCategory> categories = deriveCategoriesFromRuleAndSignals(dmr.getPolicyRule(), dmr.getContributingFactors(), dmr.getProvenance() != null ? dmr.getProvenance().name() : null);
        List<ContributingFactor> factors = deriveFactorsFromSignals(dmr.getContributingFactors(), categories);
        List<String> findings = policyResult.getContributingFactors();

        EvidenceChain chain = buildEvidenceChainFromDeniedRecord(dmr, policyResult);
        String summary = generateDeterministicSummary(PolicyDecision.BLOCK, policyResult, null, categories, factors);

        SecurityDecisionExplanation explanation = new SecurityDecisionExplanation(
                dmr.getId(),
                dmr.getCorrelationId(),
                PolicyDecision.BLOCK,
                dmr.getRiskScore(),
                dmr.getRiskLevel() != null ? dmr.getRiskLevel() : "HIGH",
                dmr.getConfidence(),
                dmr.getPolicyRule() != null ? dmr.getPolicyRule() : "SCORE_THRESHOLD_BLOCK",
                categories,
                factors,
                findings,
                chain,
                summary,
                dmr.getDeniedAt() != null ? dmr.getDeniedAt() : LocalDateTime.now()
        );

        verifyDecisionConsistencyInvariant(explanation, policyResult);
        return explanation;
    }

    // =========================================================================
    // INVARIANT VERIFICATION
    // =========================================================================

    public void verifyDecisionConsistencyInvariant(SecurityDecisionExplanation explanation, PolicyDecisionResult policyResult) {
        if (explanation.getFinalDecision() != policyResult.getDecision()) {
            throw new IllegalStateException(
                    "Security Invariant Violated: Explanation finalDecision (" + explanation.getFinalDecision() +
                            ") does not equal PolicyDecisionResult decision (" + policyResult.getDecision() + ")"
            );
        }
    }

    // =========================================================================
    // THREAT CATEGORY EXTRACTION
    // =========================================================================

    private List<ThreatCategory> extractThreatCategories(
            PolicyDecisionResult policyResult,
            AggregatedRiskAssessment riskAssessment,
            Memory memory,
            ProvenanceAnalysisResult provenanceResult,
            ContextAnalysisResult contextResult) {

        Set<ThreatCategory> categories = new LinkedHashSet<>();

        String primaryCategory = riskAssessment != null ? riskAssessment.getPrimaryCategory() : "";
        String rule = policyResult != null ? policyResult.getPolicyRule() : "";
        List<String> signals = policyResult != null ? policyResult.getContributingFactors() : List.of();

        // 1. Provenance anomalies & Trust violations
        ProvenanceType prov = memory != null ? memory.getProvenance() : null;
        if (prov == ProvenanceType.TOOL || prov == ProvenanceType.RETRIEVED || prov == ProvenanceType.UNKNOWN) {
            categories.add(ThreatCategory.PROVENANCE_ANOMALY);
            categories.add(ThreatCategory.TRUST_VIOLATION);
        } else if (provenanceResult != null && provenanceResult.getRiskScore() > 0) {
            categories.add(ThreatCategory.PROVENANCE_ANOMALY);
        }

        // 2. Prompt Injection & System Prompt Overrides
        if (primaryCategory.contains("INJECTION") || primaryCategory.contains("OVERRIDE") || containsSignal(signals, "INJECTION", "OVERRIDE")) {
            categories.add(ThreatCategory.PROMPT_INJECTION);
        }

        // 3. Behavioral Manipulation & Data Poisoning
        if (primaryCategory.contains("MANIPULATION") || primaryCategory.contains("PERSISTENCE") || rule.contains("BEHAVIORAL_MANIPULATION") || containsSignal(signals, "MANIPULATION", "PERSISTENCE", "SOCIAL_ENGINEERING")) {
            categories.add(ThreatCategory.MANIPULATION);
            categories.add(ThreatCategory.DATA_POISONING);
        }

        // 4. Sensitive Data & Secrets
        if (primaryCategory.contains("CREDENTIAL") || primaryCategory.contains("SECRET") || primaryCategory.contains("SENSITIVE") || containsSignal(signals, "CREDENTIAL", "SECRET", "API_KEY", "PASSWORD")) {
            categories.add(ThreatCategory.SENSITIVE_DATA);
        }

        // 5. Policy Violations
        if (policyResult != null && policyResult.getDecision() != PolicyDecision.ALLOW) {
            categories.add(ThreatCategory.POLICY_VIOLATION);
        }

        if (categories.isEmpty()) {
            categories.add(ThreatCategory.UNKNOWN);
        }

        return new ArrayList<>(categories);
    }

    // =========================================================================
    // CONTRIBUTING FACTORS EXTRACTION
    // =========================================================================

    private List<ContributingFactor> extractContributingFactors(
            PolicyDecisionResult policyResult,
            AggregatedRiskAssessment riskAssessment,
            Memory memory,
            ProvenanceAnalysisResult provenanceResult,
            ContextAnalysisResult contextResult) {

        List<ContributingFactor> factors = new ArrayList<>();

        if (memory != null && memory.getProvenance() != null && memory.getProvenance() != ProvenanceType.SYSTEM) {
            factors.add(new ContributingFactor(
                    ThreatCategory.PROVENANCE_ANOMALY,
                    "SUSPICIOUS_PROVENANCE",
                    "Memory originated from source type: " + memory.getProvenance(),
                    memory.getProvenance() == ProvenanceType.RETRIEVED || memory.getProvenance() == ProvenanceType.UNKNOWN ? "HIGH" : "MEDIUM"
            ));
        }

        if (riskAssessment != null && riskAssessment.getConfidence() < 0.7) {
            factors.add(new ContributingFactor(
                    ThreatCategory.POLICY_VIOLATION,
                    "ANALYZER_CONFIDENCE_LOW",
                    "Analyzer confidence score (" + String.format("%.2f", riskAssessment.getConfidence()) + ") is below deterministic threshold",
                    "MEDIUM"
            ));
        }

        if (policyResult != null && policyResult.getContributingFactors() != null) {
            for (String factorStr : policyResult.getContributingFactors()) {
                ThreatCategory cat = mapSignalToCategory(factorStr);
                factors.add(new ContributingFactor(
                        cat,
                        extractFactorId(factorStr),
                        factorStr,
                        deriveSeverityFromScore(policyResult.getRiskScore())
                ));
            }
        }

        if (factors.isEmpty()) {
            factors.add(new ContributingFactor(
                    ThreatCategory.UNKNOWN,
                    "BASELINE_RISK_CHECK",
                    "Standard risk assessment baseline evaluation",
                    "LOW"
            ));
        }

        return factors;
    }

    // =========================================================================
    // ANALYZER FINDINGS EXTRACTION
    // =========================================================================

    private List<String> extractAnalyzerFindings(
            PolicyDecisionResult policyResult,
            AggregatedRiskAssessment riskAssessment,
            Memory memory,
            ProvenanceAnalysisResult provenanceResult,
            ContextAnalysisResult contextResult) {

        List<String> findings = new ArrayList<>();

        if (provenanceResult != null && provenanceResult.getReason() != null) {
            findings.add("ProvenanceAnalyzer: [" + provenanceResult.getCategory() + "] " + provenanceResult.getReason());
        }

        if (contextResult != null && contextResult.getRiskScore() > 0) {
            findings.add("ContextAnalyzer: " + contextResult.getReason());
        }

        if (riskAssessment != null && riskAssessment.getDetectedSignals() != null) {
            findings.addAll(riskAssessment.getDetectedSignals());
        }

        if (findings.isEmpty() && policyResult != null) {
            findings.addAll(policyResult.getContributingFactors());
        }

        if (findings.isEmpty()) {
            findings.add("No elevated security findings detected during multi-layer analysis pipeline execution.");
        }

        return findings;
    }

    // =========================================================================
    // EVIDENCE CHAIN BUILDING
    // =========================================================================

    private EvidenceChain buildEvidenceChain(
            PolicyDecisionResult policyResult,
            AggregatedRiskAssessment riskAssessment,
            Memory memory,
            ProvenanceAnalysisResult provenanceResult,
            ContextAnalysisResult contextResult) {

        List<EvidenceNode> nodes = new ArrayList<>();
        PolicyDecision decision = policyResult != null ? policyResult.getDecision() : PolicyDecision.REVIEW;
        String rule = policyResult != null ? policyResult.getPolicyRule() : "DEFAULT_POLICY";
        int totalScore = policyResult != null ? policyResult.getRiskScore() : 0;

        // Node 1: Provenance Analysis
        int provScore = provenanceResult != null ? provenanceResult.getRiskScore() : (memory != null && memory.getProvenance() != ProvenanceType.SYSTEM ? 40 : 0);
        String provFinding = provenanceResult != null ? provenanceResult.getReason() : ("Provenance: " + (memory != null ? memory.getProvenance() : "UNKNOWN"));
        nodes.add(new EvidenceNode(
                "PROVENANCE",
                provFinding,
                provScore,
                provScore,
                rule,
                decision
        ));

        // Node 2: Content Rule Analysis
        int ruleScore = riskAssessment != null && riskAssessment.getDimensionalScores().containsKey("injectionRisk") ?
                riskAssessment.getDimensionalScores().get("injectionRisk") : (totalScore > provScore ? totalScore - provScore : 0);
        String ruleFinding = riskAssessment != null && riskAssessment.getPrimaryReason() != null ? riskAssessment.getPrimaryReason() : "Content policy check";
        nodes.add(new EvidenceNode(
                "RULE",
                ruleFinding,
                ruleScore,
                Math.max(provScore, ruleScore),
                rule,
                decision
        ));

        // Node 3: Policy Engine Decision
        nodes.add(new EvidenceNode(
                "POLICY_ENGINE",
                "Evaluated rule: " + rule + " -> Final decision: " + decision,
                totalScore,
                totalScore,
                rule,
                decision
        ));

        return new EvidenceChain(nodes, totalScore, rule, decision);
    }

    // =========================================================================
    // DETERMINISTIC SUMMARY GENERATION
    // =========================================================================

    private String generateDeterministicSummary(
            PolicyDecision decision,
            PolicyDecisionResult policyResult,
            AggregatedRiskAssessment riskAssessment,
            List<ThreatCategory> threatCategories,
            List<ContributingFactor> contributingFactors) {

        int score = policyResult != null ? policyResult.getRiskScore() : 0;
        String rule = policyResult != null ? policyResult.getPolicyRule() : "DEFAULT_POLICY";

        switch (decision) {
            case ALLOW:
                return "Memory ALLOWED: aggregate risk score (" + score + "/100) remained below the active review threshold and no blocking policy rule was triggered [Policy: " + rule + "].";
            case REVIEW:
                return "Memory QUARANTINED: risk signals produced a medium-confidence security concern requiring operator verification [Risk: " + score + "/100, Policy: " + rule + "].";
            case BLOCK:
                return "Memory DENIED: aggregate security risk exceeded the blocking threshold or a critical policy rule was triggered [Risk: " + score + "/100, Policy: " + rule + "].";
            default:
                return "Memory security decision processed [Decision: " + decision + ", Policy: " + rule + "].";
        }
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================

    private PolicyDecision parseDecisionFromAction(String action) {
        if (action == null) return PolicyDecision.REVIEW;
        String act = action.toUpperCase();
        if (act.contains("ALLOW") || act.contains("PERMIT")) return PolicyDecision.ALLOW;
        if (act.contains("BLOCK") || act.contains("DENI")) return PolicyDecision.BLOCK;
        return PolicyDecision.REVIEW;
    }

    private List<ThreatCategory> parseThreatCategoriesFromLog(SecurityLog log) {
        Set<ThreatCategory> set = new LinkedHashSet<>();
        String threatType = log.getThreatType();
        String signals = log.getContributingSignals();

        if (threatType != null) {
            set.addAll(deriveCategoriesFromRuleAndSignals(threatType, signals, log.getProvenance()));
        }
        if (set.isEmpty()) {
            set.add(ThreatCategory.UNKNOWN);
        }
        return new ArrayList<>(set);
    }

    private List<ContributingFactor> parseContributingFactorsFromLog(SecurityLog log, List<ThreatCategory> categories) {
        List<ContributingFactor> factors = new ArrayList<>();
        if (log.getContributingSignals() != null && !log.getContributingSignals().isEmpty()) {
            for (String sig : log.getContributingSignals().split("\\s*\\|\\s*")) {
                factors.add(new ContributingFactor(
                        categories.isEmpty() ? ThreatCategory.UNKNOWN : categories.get(0),
                        extractFactorId(sig),
                        sig,
                        log.getRiskLevel() != null ? log.getRiskLevel() : "MEDIUM"
                ));
            }
        }
        if (factors.isEmpty()) {
            factors.add(new ContributingFactor(
                    ThreatCategory.UNKNOWN,
                    "SECURITY_LOG_ENTRY",
                    log.getExplanation() != null ? log.getExplanation() : "Persisted security log record",
                    log.getRiskLevel() != null ? log.getRiskLevel() : "LOW"
            ));
        }
        return factors;
    }

    private List<ThreatCategory> deriveCategoriesFromRuleAndSignals(String rule, String signalsStr, String provenanceStr) {
        Set<ThreatCategory> set = new LinkedHashSet<>();

        if (provenanceStr != null && (provenanceStr.contains("RETRIEVED") || provenanceStr.contains("TOOL") || provenanceStr.contains("UNKNOWN"))) {
            set.add(ThreatCategory.PROVENANCE_ANOMALY);
            set.add(ThreatCategory.TRUST_VIOLATION);
        }

        String combined = ((rule != null ? rule : "") + " " + (signalsStr != null ? signalsStr : "")).toUpperCase();

        if (combined.contains("INJECTION") || combined.contains("OVERRIDE")) {
            set.add(ThreatCategory.PROMPT_INJECTION);
        }
        if (combined.contains("MANIPULATION") || combined.contains("PERSISTENCE")) {
            set.add(ThreatCategory.MANIPULATION);
            set.add(ThreatCategory.DATA_POISONING);
        }
        if (combined.contains("CREDENTIAL") || combined.contains("SECRET")) {
            set.add(ThreatCategory.SENSITIVE_DATA);
        }
        if (combined.contains("SCORE_THRESHOLD") || combined.contains("CRITICAL") || combined.contains("POLICY")) {
            set.add(ThreatCategory.POLICY_VIOLATION);
        }

        if (set.isEmpty()) {
            set.add(ThreatCategory.UNKNOWN);
        }
        return new ArrayList<>(set);
    }

    private List<ContributingFactor> deriveFactorsFromSignals(String signalsStr, List<ThreatCategory> categories) {
        List<ContributingFactor> factors = new ArrayList<>();
        if (signalsStr != null && !signalsStr.isEmpty()) {
            for (String sig : signalsStr.split("\\s*\\|\\s*")) {
                factors.add(new ContributingFactor(
                        categories.isEmpty() ? ThreatCategory.UNKNOWN : categories.get(0),
                        extractFactorId(sig),
                        sig,
                        "MEDIUM"
                ));
            }
        }
        if (factors.isEmpty()) {
            factors.add(new ContributingFactor(
                    ThreatCategory.UNKNOWN,
                    "EVALUATED_SECURITY_RECORD",
                    "Record evaluated in persistence store",
                    "MEDIUM"
            ));
        }
        return factors;
    }

    private EvidenceChain buildEvidenceChainFromLog(SecurityLog log, PolicyDecisionResult policyResult) {
        List<EvidenceNode> nodes = new ArrayList<>();
        nodes.add(new EvidenceNode(
                log.getAnalyzerType() != null ? log.getAnalyzerType() : "LOG_AUDIT",
                log.getExplanation() != null ? log.getExplanation() : "Audit log evidence record",
                log.getRiskScore(),
                log.getRiskScore(),
                log.getThreatType() != null ? log.getThreatType() : "POLICY_RULE",
                policyResult.getDecision()
        ));
        return new EvidenceChain(nodes, log.getRiskScore(), log.getThreatType() != null ? log.getThreatType() : "POLICY_RULE", policyResult.getDecision());
    }

    private EvidenceChain buildEvidenceChainFromQuarantinedMemory(QuarantinedMemory qm, PolicyDecisionResult policyResult) {
        List<EvidenceNode> nodes = new ArrayList<>();
        nodes.add(new EvidenceNode(
                "QUARANTINE_STORE",
                qm.getExplanation() != null ? qm.getExplanation() : "Memory isolated in quarantine store",
                qm.getRiskScore(),
                qm.getRiskScore(),
                qm.getPolicyRule() != null ? qm.getPolicyRule() : "SCORE_THRESHOLD_REVIEW",
                PolicyDecision.REVIEW
        ));
        return new EvidenceChain(nodes, qm.getRiskScore(), qm.getPolicyRule() != null ? qm.getPolicyRule() : "SCORE_THRESHOLD_REVIEW", PolicyDecision.REVIEW);
    }

    private EvidenceChain buildEvidenceChainFromDeniedRecord(DeniedMemoryRecord dmr, PolicyDecisionResult policyResult) {
        List<EvidenceNode> nodes = new ArrayList<>();
        nodes.add(new EvidenceNode(
                "DENIED_TOMBSTONE_STORE",
                "Denied tombstone hash: " + dmr.getContentHash(),
                dmr.getRiskScore(),
                dmr.getRiskScore(),
                dmr.getPolicyRule() != null ? dmr.getPolicyRule() : "SCORE_THRESHOLD_BLOCK",
                PolicyDecision.BLOCK
        ));
        return new EvidenceChain(nodes, dmr.getRiskScore(), dmr.getPolicyRule() != null ? dmr.getPolicyRule() : "SCORE_THRESHOLD_BLOCK", PolicyDecision.BLOCK);
    }

    private ThreatCategory mapSignalToCategory(String signal) {
        if (signal == null) return ThreatCategory.UNKNOWN;
        String sigUpper = signal.toUpperCase();
        if (sigUpper.contains("PROVENANCE")) return ThreatCategory.PROVENANCE_ANOMALY;
        if (sigUpper.contains("INJECTION") || sigUpper.contains("OVERRIDE")) return ThreatCategory.PROMPT_INJECTION;
        if (sigUpper.contains("MANIPULATION") || sigUpper.contains("PERSISTENCE")) return ThreatCategory.MANIPULATION;
        if (sigUpper.contains("CREDENTIAL") || sigUpper.contains("SECRET")) return ThreatCategory.SENSITIVE_DATA;
        return ThreatCategory.POLICY_VIOLATION;
    }

    private String extractFactorId(String signalStr) {
        if (signalStr == null || signalStr.isEmpty()) return "SECURITY_SIGNAL";
        String clean = signalStr.replaceAll("[^a-zA-Z0-9_]", "_").toUpperCase();
        if (clean.length() > 30) return clean.substring(0, 30);
        return clean;
    }

    private String deriveSeverityFromScore(int score) {
        if (score >= 80) return "HIGH";
        if (score >= 50) return "MEDIUM";
        return "LOW";
    }

    private boolean containsSignal(List<String> signals, String... terms) {
        if (signals == null || signals.isEmpty()) return false;
        for (String sig : signals) {
            String upper = sig.toUpperCase();
            for (String term : terms) {
                if (upper.contains(term)) return true;
            }
        }
        return false;
    }
}

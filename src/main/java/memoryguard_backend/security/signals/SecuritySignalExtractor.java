package memoryguard_backend.security.signals;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.ProvenanceType;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service responsible for extracting structured security signals & risk features from memory items.
 * <p>
 * This layer converts memory content, metadata, provenance, and contextual information into
 * quantitative security features (0.0 to 1.0) and explainable indicators.
 * <p>
 * MUST BE STRICTLY DETERMINISTIC AND NON-DECISION MAKING.
 * Does NOT make final ALLOW/BLOCK decisions and does NOT invoke LLMs or external APIs.
 */
@Component
public class SecuritySignalExtractor {

    private static final String DETECTOR_PROVENANCE = "provenance-detector";
    private static final String DETECTOR_COMPLETENESS = "completeness-detector";
    private static final String DETECTOR_CONTEXT = "context-consistency-detector";
    private static final String DETECTOR_INSTRUCTION = "instruction-analysis-detector";
    private static final String DETECTOR_PRIVILEGE = "privilege-security-detector";
    private static final String DETECTOR_TEMPORAL = "temporal-metadata-detector";

    /**
     * Extract security signals for a Memory item using system clock for temporal checks.
     */
    public SecuritySignals extract(Memory memory) {
        return extract(memory, null, LocalDateTime.now());
    }

    /**
     * Extract security signals for a Memory item with optional extra context map and explicit reference time.
     */
    public SecuritySignals extract(Memory memory, Map<String, Object> additionalContext, LocalDateTime referenceTime) {
        if (referenceTime == null) {
            referenceTime = LocalDateTime.now();
        }

        List<SecurityIndicator> indicators = new ArrayList<>();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("extractedAt", referenceTime.toString());
        metadata.put("extractorVersion", "1.0");

        if (additionalContext != null && !additionalContext.isEmpty()) {
            metadata.put("additionalContextKeys", new ArrayList<>(additionalContext.keySet()));
        }

        if (memory == null) {
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.MISSING_PROVENANCE,
                    SecurityIndicator.SEVERITY_CRITICAL,
                    "Memory entity is null; signals defaulted to maximum uncertainty",
                    DETECTOR_COMPLETENESS
            ));

            return new SecuritySignals(
                    null,
                    null,
                    0.0, // provenanceTrustScore
                    0.0, // sourceReliabilityScore
                    0.0, // contextConsistencyScore
                    0.0, // provenanceCompletenessScore
                    0.0, // sensitivityScore
                    1.0, // anomalyScore
                    0.0, // instructionLikeScore
                    0.0, // privilegeRiskScore
                    0.0, // temporalAnomalyScore
                    indicators,
                    metadata
            );
        }

        Long memoryId = memory.getId();
        String correlationId = memory.getCorrelationId();
        String content = memory.getContent() != null ? memory.getContent() : "";

        // 1. Provenance & Source Trust Analysis
        ProvenanceTrustResult provResult = analyzeProvenanceAndSource(memory);
        indicators.addAll(provResult.indicators);

        // 2. Provenance Completeness Analysis
        CompletenessResult compResult = analyzeCompleteness(memory);
        indicators.addAll(compResult.indicators);

        // 3. Context Consistency Analysis
        ContextConsistencyResult contextResult = analyzeContextConsistency(memory, additionalContext);
        indicators.addAll(contextResult.indicators);

        // 4. Instruction-Like Behavior Analysis
        InstructionAnalysisResult instructionResult = analyzeInstructionPatterns(content);
        indicators.addAll(instructionResult.indicators);

        // 5. Privilege & Sensitivity Analysis
        PrivilegeSensitivityResult privSensResult = analyzePrivilegeAndSensitivity(content);
        indicators.addAll(privSensResult.indicators);

        // 6. Metadata Anomalies & Temporal Analysis
        TemporalAnomalyResult temporalResult = analyzeTemporalAndMetadataAnomalies(memory, referenceTime);
        indicators.addAll(temporalResult.indicators);

        metadata.put("indicatorCount", indicators.size());

        return new SecuritySignals(
                memoryId,
                correlationId,
                provResult.provenanceTrustScore,
                provResult.sourceReliabilityScore,
                contextResult.contextConsistencyScore,
                compResult.provenanceCompletenessScore,
                privSensResult.sensitivityScore,
                temporalResult.anomalyScore,
                instructionResult.instructionLikeScore,
                privSensResult.privilegeRiskScore,
                temporalResult.temporalAnomalyScore,
                indicators,
                metadata
        );
    }

    // =========================================================================
    // DETECTOR 1: PROVENANCE & SOURCE TRUST
    // =========================================================================

    private record ProvenanceTrustResult(
            double provenanceTrustScore,
            double sourceReliabilityScore,
            List<SecurityIndicator> indicators
    ) {}

    private ProvenanceTrustResult analyzeProvenanceAndSource(Memory memory) {
        List<SecurityIndicator> indicators = new ArrayList<>();
        ProvenanceType prov = memory.getProvenance();
        if (prov == null) {
            prov = ProvenanceType.UNKNOWN;
        }

        double trustScore;
        double reliabilityScore;

        switch (prov) {
            case SYSTEM -> {
                trustScore = 1.0;
                reliabilityScore = 1.0;
            }
            case USER -> {
                trustScore = 0.9;
                reliabilityScore = 0.9;
            }
            case AGENT -> {
                trustScore = 0.8;
                reliabilityScore = 0.85;
            }
            case TOOL -> {
                trustScore = 0.6;
                reliabilityScore = 0.7;
            }
            case RETRIEVED -> {
                trustScore = 0.4;
                reliabilityScore = 0.5;
                indicators.add(new SecurityIndicator(
                        SecurityIndicator.UNTRUSTED_SOURCE,
                        SecurityIndicator.SEVERITY_MEDIUM,
                        "Memory origin is external RETRIEVED RAG/scraping source carrying potential indirect injection risk",
                        DETECTOR_PROVENANCE
                ));
            }
            case UNKNOWN -> {
                trustScore = 0.2;
                reliabilityScore = 0.2;
                indicators.add(new SecurityIndicator(
                        SecurityIndicator.UNTRUSTED_SOURCE,
                        SecurityIndicator.SEVERITY_HIGH,
                        "Memory origin is UNKNOWN or unverified",
                        DETECTOR_PROVENANCE
                ));
            }
            default -> {
                trustScore = 0.2;
                reliabilityScore = 0.2;
            }
        }

        return new ProvenanceTrustResult(trustScore, reliabilityScore, indicators);
    }

    // =========================================================================
    // DETECTOR 2: PROVENANCE COMPLETENESS
    // =========================================================================

    private record CompletenessResult(
            double provenanceCompletenessScore,
            List<SecurityIndicator> indicators
    ) {}

    private CompletenessResult analyzeCompleteness(Memory memory) {
        List<SecurityIndicator> indicators = new ArrayList<>();
        double completeness = 1.0;

        if (memory.getProvenance() == null || memory.getProvenance() == ProvenanceType.UNKNOWN) {
            completeness -= 0.4;
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.MISSING_PROVENANCE,
                    SecurityIndicator.SEVERITY_MEDIUM,
                    "Memory provenance metadata is UNKNOWN or omitted",
                    DETECTOR_COMPLETENESS
            ));
        }

        if (memory.getAgentId() == null || memory.getAgentId() <= 0) {
            completeness -= 0.3;
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.INCOMPLETE_PROVENANCE,
                    SecurityIndicator.SEVERITY_MEDIUM,
                    "Memory lacks a valid agent identifier context",
                    DETECTOR_COMPLETENESS
            ));
        }

        if (memory.getMemoryType() == null || memory.getMemoryType().trim().isEmpty()) {
            completeness -= 0.3;
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.INCOMPLETE_PROVENANCE,
                    SecurityIndicator.SEVERITY_LOW,
                    "Memory type classification is missing or blank",
                    DETECTOR_COMPLETENESS
            ));
        }

        return new CompletenessResult(Math.max(0.0, completeness), indicators);
    }

    // =========================================================================
    // DETECTOR 3: CONTEXT CONSISTENCY
    // =========================================================================

    private record ContextConsistencyResult(
            double contextConsistencyScore,
            List<SecurityIndicator> indicators
    ) {}

    private ContextConsistencyResult analyzeContextConsistency(Memory memory, Map<String, Object> extraContext) {
        List<SecurityIndicator> indicators = new ArrayList<>();
        double consistency = 1.0;

        // Check agentId validity
        if (memory.getAgentId() == null || memory.getAgentId() <= 0) {
            consistency -= 0.4;
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.CONTEXT_MISMATCH,
                    SecurityIndicator.SEVERITY_HIGH,
                    "Memory agent ID is invalid or missing",
                    DETECTOR_CONTEXT
            ));
        }

        // Check timestamps ordering: createdAt should not be strictly after updatedAt
        if (memory.getCreatedAt() != null && memory.getUpdatedAt() != null && memory.getCreatedAt().isAfter(memory.getUpdatedAt())) {
            consistency -= 0.5;
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.CONTEXT_MISMATCH,
                    SecurityIndicator.SEVERITY_HIGH,
                    "Memory creation timestamp occurs after modification timestamp",
                    DETECTOR_CONTEXT
            ));
        }

        // Provenance & memoryType cross-check
        ProvenanceType prov = memory.getProvenance();
        String memType = memory.getMemoryType() != null ? memory.getMemoryType().toUpperCase() : "";

        if (prov == ProvenanceType.SYSTEM && (memType.contains("USER_PREFERENCE") || memType.contains("CHAT_HISTORY"))) {
            consistency -= 0.2;
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.CONTEXT_MISMATCH,
                    SecurityIndicator.SEVERITY_LOW,
                    "SYSTEM provenance configured with user-interactive memory type: " + memType,
                    DETECTOR_CONTEXT
            ));
        }

        // Additional context payload cross-checks if provided
        if (extraContext != null) {
            if (extraContext.containsKey("expectedAgentId")) {
                Object expectedIdObj = extraContext.get("expectedAgentId");
                if (expectedIdObj instanceof Long expectedId && !expectedId.equals(memory.getAgentId())) {
                    consistency -= 0.4;
                    indicators.add(new SecurityIndicator(
                            SecurityIndicator.CONTEXT_MISMATCH,
                            SecurityIndicator.SEVERITY_HIGH,
                            "Agent ID mismatch: memory has " + memory.getAgentId() + " but session context expected " + expectedId,
                            DETECTOR_CONTEXT
                    ));
                }
            }
        }

        return new ContextConsistencyResult(Math.max(0.0, consistency), indicators);
    }

    // =========================================================================
    // DETECTOR 4: INSTRUCTION-LIKE BEHAVIOR
    // =========================================================================

    private record InstructionAnalysisResult(
            double instructionLikeScore,
            List<SecurityIndicator> indicators
    ) {}

    private InstructionAnalysisResult analyzeInstructionPatterns(String content) {
        List<SecurityIndicator> indicators = new ArrayList<>();
        if (content == null || content.trim().isEmpty()) {
            return new InstructionAnalysisResult(0.0, indicators);
        }

        String lower = content.toLowerCase();
        double score = 0.0;

        // Pattern 1: Strong Prompt Override / Jailbreak phrases
        String[] highOverridePhrases = {
                "ignore previous instructions",
                "ignore all previous instructions",
                "disregard previous instructions",
                "disregard all previous instructions",
                "forget previous instructions",
                "override system prompt",
                "override the system instructions",
                "bypass security restrictions",
                "jailbreak",
                "developer mode",
                "dan mode"
        };

        for (String phrase : highOverridePhrases) {
            if (lower.contains(phrase)) {
                score = Math.max(score, 0.85);
                indicators.add(new SecurityIndicator(
                        SecurityIndicator.INSTRUCTION_LIKE_CONTENT,
                        SecurityIndicator.SEVERITY_HIGH,
                        "Memory contains prompt override or jailbreak phrase: '" + phrase + "'",
                        DETECTOR_INSTRUCTION
                ));
            }
        }

        // Pattern 2: System directive directives
        String[] systemDirectivePhrases = {
                "system instruction",
                "system prompt",
                "you must obey",
                "you must follow",
                "do not follow",
                "always follow this instruction",
                "follow these instructions instead",
                "administrator message",
                "developer instruction"
        };

        for (String phrase : systemDirectivePhrases) {
            if (lower.contains(phrase)) {
                score = Math.max(score, 0.65);
                indicators.add(new SecurityIndicator(
                        SecurityIndicator.INSTRUCTION_LIKE_CONTENT,
                        SecurityIndicator.SEVERITY_MEDIUM,
                        "Memory contains instruction-oriented system directive phrase: '" + phrase + "'",
                        DETECTOR_INSTRUCTION
                ));
            }
        }

        // Pattern 3: Imperative system command tone
        String[] imperativePhrases = {
                "override",
                "execute",
                "administrator",
                "from now on you are",
                "act as an unrestricted"
        };

        int countImperative = 0;
        for (String word : imperativePhrases) {
            if (lower.contains(word)) {
                countImperative++;
            }
        }

        if (countImperative >= 2 && score < 0.5) {
            score = 0.5;
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.INSTRUCTION_LIKE_CONTENT,
                    SecurityIndicator.SEVERITY_MEDIUM,
                    "Memory exhibits multiple imperative command terms",
                    DETECTOR_INSTRUCTION
            ));
        }

        return new InstructionAnalysisResult(Math.min(1.0, score), indicators);
    }

    // =========================================================================
    // DETECTOR 5: PRIVILEGE & SENSITIVITY RELEVANCE
    // =========================================================================

    private record PrivilegeSensitivityResult(
            double privilegeRiskScore,
            double sensitivityScore,
            List<SecurityIndicator> indicators
    ) {}

    private PrivilegeSensitivityResult analyzePrivilegeAndSensitivity(String content) {
        List<SecurityIndicator> indicators = new ArrayList<>();
        if (content == null || content.trim().isEmpty()) {
            return new PrivilegeSensitivityResult(0.0, 0.0, indicators);
        }

        String lower = content.toLowerCase();
        double privilegeScore = 0.0;
        double sensitivityScore = 0.0;

        // Credentials / Authentication Secrets exposure or mention
        String[] credentialKeywords = {
                "password", "passwd", "api key", "apikey", "secret", "token", "private key", "access_token", "bearer"
        };

        boolean hasCred = false;
        for (String kw : credentialKeywords) {
            if (lower.contains(kw)) {
                hasCred = true;
                break;
            }
        }

        if (hasCred) {
            // Check for actual assignment or exposure pattern
            String[] exposurePatterns = {
                    "password is", "password:", "passwd:", "secret is", "secret:", "api key is", "api key:", "token is", "token:"
            };

            boolean exposed = false;
            for (String ep : exposurePatterns) {
                if (lower.contains(ep)) {
                    exposed = true;
                    break;
                }
            }

            if (exposed) {
                privilegeScore = Math.max(privilegeScore, 0.9);
                sensitivityScore = Math.max(sensitivityScore, 0.95);
                indicators.add(new SecurityIndicator(
                        SecurityIndicator.PRIVILEGE_SECURITY_RELEVANCE,
                        SecurityIndicator.SEVERITY_HIGH,
                        "Memory contains explicit credential or authentication secret exposure pattern",
                        DETECTOR_PRIVILEGE
                ));
            } else {
                // Preventive guidance check
                boolean isPreventive = lower.contains("never store") || lower.contains("do not store") ||
                                       lower.contains("never share") || lower.contains("update your password");
                if (isPreventive) {
                    privilegeScore = Math.max(privilegeScore, 0.2);
                    sensitivityScore = Math.max(sensitivityScore, 0.2);
                } else {
                    privilegeScore = Math.max(privilegeScore, 0.5);
                    sensitivityScore = Math.max(sensitivityScore, 0.6);
                    indicators.add(new SecurityIndicator(
                            SecurityIndicator.PRIVILEGE_SECURITY_RELEVANCE,
                            SecurityIndicator.SEVERITY_MEDIUM,
                            "Memory references authentication credentials or secret key terminology",
                            DETECTOR_PRIVILEGE
                    ));
                }
            }
        }

        // Administrative & System Privileges keywords
        String[] adminKeywords = {
                "root privileges", "sudo", "administrator access", "admin rights", "chmod 777", "eval(", "exec(", "/etc/passwd", "system32"
        };

        for (String kw : adminKeywords) {
            if (lower.contains(kw)) {
                privilegeScore = Math.max(privilegeScore, 0.85);
                indicators.add(new SecurityIndicator(
                        SecurityIndicator.PRIVILEGE_SECURITY_RELEVANCE,
                        SecurityIndicator.SEVERITY_HIGH,
                        "Memory contains high-privilege system/admin keyword: '" + kw + "'",
                        DETECTOR_PRIVILEGE
                ));
            }
        }

        // PII & Sensitive Financial Data keywords
        String[] sensitiveKeywords = {
                "aadhaar", "ssn", "social security", "credit card", "debit card", "bank account", "passport number"
        };

        for (String kw : sensitiveKeywords) {
            if (lower.contains(kw)) {
                sensitivityScore = Math.max(sensitivityScore, 0.85);
                indicators.add(new SecurityIndicator(
                        SecurityIndicator.SENSITIVE_CONTENT,
                        SecurityIndicator.SEVERITY_HIGH,
                        "Memory contains sensitive PII or financial data reference: '" + kw + "'",
                        DETECTOR_PRIVILEGE
                ));
            }
        }

        return new PrivilegeSensitivityResult(privilegeScore, sensitivityScore, indicators);
    }

    // =========================================================================
    // DETECTOR 6: TEMPORAL ANOMALIES & SUSPICIOUS METADATA
    // =========================================================================

    private record TemporalAnomalyResult(
            double temporalAnomalyScore,
            double anomalyScore,
            List<SecurityIndicator> indicators
    ) {}

    private TemporalAnomalyResult analyzeTemporalAndMetadataAnomalies(Memory memory, LocalDateTime referenceTime) {
        List<SecurityIndicator> indicators = new ArrayList<>();
        double tempScore = 0.0;
        double anomalyScore = 0.0;

        // Check for Future Timestamps (allowing a 60-second clock skew window)
        LocalDateTime nowPlusTolerance = referenceTime.plusSeconds(60);

        if (memory.getCreatedAt() != null && memory.getCreatedAt().isAfter(nowPlusTolerance)) {
            tempScore = Math.max(tempScore, 0.9);
            anomalyScore = Math.max(anomalyScore, 0.85);
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.FUTURE_TIMESTAMP,
                    SecurityIndicator.SEVERITY_HIGH,
                    "Memory createdAt timestamp (" + memory.getCreatedAt() + ") is in the future relative to system reference time (" + referenceTime + ")",
                    DETECTOR_TEMPORAL
            ));
        }

        if (memory.getUpdatedAt() != null && memory.getUpdatedAt().isAfter(nowPlusTolerance)) {
            tempScore = Math.max(tempScore, 0.8);
            anomalyScore = Math.max(anomalyScore, 0.75);
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.FUTURE_TIMESTAMP,
                    SecurityIndicator.SEVERITY_MEDIUM,
                    "Memory updatedAt timestamp (" + memory.getUpdatedAt() + ") is in the future",
                    DETECTOR_TEMPORAL
            ));
        }

        // Check for Impossible Timestamp Ordering
        if (memory.getCreatedAt() != null && memory.getUpdatedAt() != null && memory.getCreatedAt().isAfter(memory.getUpdatedAt())) {
            tempScore = Math.max(tempScore, 0.85);
            anomalyScore = Math.max(anomalyScore, 0.8);
            indicators.add(new SecurityIndicator(
                    SecurityIndicator.IMPOSSIBLE_TIMESTAMP_ORDER,
                    SecurityIndicator.SEVERITY_HIGH,
                    "Memory createdAt timestamp (" + memory.getCreatedAt() + ") is after updatedAt timestamp (" + memory.getUpdatedAt() + ")",
                    DETECTOR_TEMPORAL
            ));
        }

        // Content length anomaly
        if (memory.getContent() != null) {
            int len = memory.getContent().length();
            if (len > 0 && memory.getContent().trim().isEmpty()) {
                anomalyScore = Math.max(anomalyScore, 0.6);
                indicators.add(new SecurityIndicator(
                        SecurityIndicator.SUSPICIOUS_METADATA,
                        SecurityIndicator.SEVERITY_MEDIUM,
                        "Memory content contains non-zero raw length but consists entirely of whitespace characters",
                        DETECTOR_TEMPORAL
                ));
            }
        }

        return new TemporalAnomalyResult(tempScore, anomalyScore, indicators);
    }
}

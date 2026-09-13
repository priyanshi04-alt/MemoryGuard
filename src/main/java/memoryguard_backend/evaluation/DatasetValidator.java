package memoryguard_backend.evaluation;

import java.util.*;

public class DatasetValidator {

    public static final Set<String> ALLOWED_DECISIONS = Set.of("ALLOW", "REVIEW", "BLOCK");
    public static final Set<String> ALLOWED_RISK_LEVELS = Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL");

    public static final Set<String> REQUIRED_CATEGORIES = Set.of(
            "NORMAL",
            "PROMPT_INJECTION",
            "INSTRUCTION_HIJACKING",
            "MALICIOUS_PERSISTENT_MEMORY",
            "SENSITIVE_INFORMATION",
            "MISLEADING_MEMORY",
            "TRUSTED_SOURCE",
            "UNTRUSTED_SOURCE",
            "AMBIGUOUS"
    );

    /**
     * Validates a list of evaluation scenarios for schema correctness, uniqueness, and category coverage.
     * Throws DatasetValidationException if malformed or incomplete.
     */
    public void validate(List<EvaluationScenario> scenarios) {
        if (scenarios == null || scenarios.isEmpty()) {
            throw new DatasetValidationException("Benchmark dataset scenarios list cannot be null or empty.");
        }

        Set<String> seenIds = new HashSet<>();
        Set<String> representedCategories = new HashSet<>();

        for (int i = 0; i < scenarios.size(); i++) {
            EvaluationScenario s = scenarios.get(i);
            String indexStr = "At index " + i;

            if (s == null) {
                throw new DatasetValidationException(indexStr + ": Evaluation scenario record cannot be null.");
            }

            String id = s.getId();
            if (id == null || id.trim().isEmpty()) {
                throw new DatasetValidationException(indexStr + ": Missing required field 'caseId' / 'id'.");
            }
            if (!seenIds.add(id.trim())) {
                throw new DatasetValidationException(indexStr + ": Duplicate case ID detected: '" + id + "'. Case IDs must be unique.");
            }

            if (s.getMemoryContent() == null || s.getMemoryContent().trim().isEmpty()) {
                throw new DatasetValidationException(indexStr + " (ID: " + id + "): Missing required field 'memoryContent'.");
            }

            if (s.getProvenance() == null || s.getProvenance().trim().isEmpty()) {
                throw new DatasetValidationException(indexStr + " (ID: " + id + "): Missing required field 'provenance'.");
            }

            String cat = s.getExpectedCategory();
            if (cat == null || cat.trim().isEmpty()) {
                throw new DatasetValidationException(indexStr + " (ID: " + id + "): Missing required field 'expectedCategory'.");
            }
            representedCategories.add(normalizeCategory(cat.trim()));

            String decision = s.getExpectedDecision();
            if (decision == null || decision.trim().isEmpty()) {
                throw new DatasetValidationException(indexStr + " (ID: " + id + "): Missing required field 'expectedDecision'.");
            }
            if (!ALLOWED_DECISIONS.contains(decision.trim().toUpperCase())) {
                throw new DatasetValidationException(indexStr + " (ID: " + id + "): Invalid expectedDecision '" + decision + "'. Allowed values: " + ALLOWED_DECISIONS);
            }

            String riskLevel = s.getExpectedRiskLevel();
            if (riskLevel != null && !riskLevel.trim().isEmpty()) {
                if (!ALLOWED_RISK_LEVELS.contains(riskLevel.trim().toUpperCase())) {
                    throw new DatasetValidationException(indexStr + " (ID: " + id + "): Invalid expectedRiskLevel '" + riskLevel + "'. Allowed values: " + ALLOWED_RISK_LEVELS);
                }
            }
        }

        // Verify required category coverage
        Set<String> missingCategories = new HashSet<>();
        for (String reqCat : REQUIRED_CATEGORIES) {
            if (!representedCategories.contains(reqCat)) {
                missingCategories.add(reqCat);
            }
        }

        if (!missingCategories.isEmpty()) {
            throw new DatasetValidationException("Dataset fails required category coverage. Missing categories: " + missingCategories);
        }
    }

    /**
     * Maps specific dataset category aliases to normalized evaluation categories.
     */
    public String normalizeCategory(String category) {
        if (category == null) return "NORMAL";
        String upper = category.toUpperCase().trim();

        if (upper.equals("BENIGN") || upper.equals("TRUSTED") || upper.equals("NORMAL")) return "NORMAL";
        if (upper.contains("PROMPT_INJECTION") || upper.equals("DIRECT_PROMPT_INJECTION") || upper.equals("INDIRECT_PROMPT_INJECTION")) return "PROMPT_INJECTION";
        if (upper.contains("INSTRUCTION_HIJACKING") || upper.contains("INSTRUCTION_OVERRIDE")) return "INSTRUCTION_HIJACKING";
        if (upper.contains("MALICIOUS_PERSISTENT") || upper.contains("MEMORY_POISONING") || upper.contains("MALICIOUS_SLEEPER_MEMORY")) return "MALICIOUS_PERSISTENT_MEMORY";
        if (upper.contains("SENSITIVE") || upper.contains("SECRET_LEAKAGE") || upper.contains("CREDENTIAL")) return "SENSITIVE_INFORMATION";
        if (upper.contains("MISLEADING") || upper.contains("CONTRADICTORY_MEMORY") || upper.contains("SOCIAL_ENGINEERING")) return "MISLEADING_MEMORY";
        if (upper.equals("TRUSTED_SOURCE")) return "TRUSTED_SOURCE";
        if (upper.equals("UNTRUSTED_SOURCE")) return "UNTRUSTED_SOURCE";
        if (upper.contains("AMBIGUOUS") || upper.contains("SAFE_BUT_AMBIGUOUS") || upper.contains("OBFUSCATED_EVASIVE")) return "AMBIGUOUS";

        return upper;
    }
}

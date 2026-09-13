package memoryguard_backend.evaluation;

public enum EvaluationMode {
    RULES_ONLY,
    RULES_PLUS_AI,
    COMPARATIVE;

    public static EvaluationMode fromString(String mode) {
        if (mode == null || mode.trim().isEmpty()) {
            return RULES_PLUS_AI;
        }
        String upper = mode.toUpperCase().trim();
        if (upper.contains("RULES_ONLY") || upper.equals("RULES")) {
            return RULES_ONLY;
        }
        if (upper.contains("COMPARATIVE") || upper.equals("COMPARE")) {
            return COMPARATIVE;
        }
        return RULES_PLUS_AI;
    }
}

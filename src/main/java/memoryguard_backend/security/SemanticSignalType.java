package memoryguard_backend.security;

/**
 * Enum representing granular semantic threat and content categories detected during semantic security analysis.
 */
public enum SemanticSignalType {

    /**
     * Indirect prompt injection hidden within memory content.
     */
    PROMPT_INJECTION("Indirect prompt injection attempt hidden within memory content", 85),

    /**
     * Attempt to override system, developer, or agent core instructions.
     */
    INSTRUCTION_OVERRIDE("Attempt to override system, developer, or agent core instructions", 80),

    /**
     * Intent to acquire or execute elevated system/administrative privileges.
     */
    PRIVILEGE_ESCALATION("Intent to acquire or execute elevated system or administrative privileges", 85),

    /**
     * Attempt to manipulate agent tool call behavior or execute unauthorized functions.
     */
    TOOL_MANIPULATION("Attempt to manipulate agent tool execution or invoke unauthorized functions", 85),

    /**
     * Attempt to extract, leak, or expose credentials, API keys, or system secrets.
     */
    SECRET_EXFILTRATION("Attempt to extract, leak, or expose credentials or system secrets", 90),

    /**
     * Pretexting, impersonation, or social engineering targeting agent trust.
     */
    SOCIAL_ENGINEERING("Pretexting, impersonation, or social engineering targeting agent trust", 75),

    /**
     * Instruction attempting to persistently alter future agent behavior, memory, or state.
     */
    MALICIOUS_PERSISTENCE("Instruction attempting to persistently alter future agent memory or state", 85),

    /**
     * Attempt to confuse, manipulate, or corrupt agent session or conversation context.
     */
    CONTEXT_MANIPULATION("Attempt to manipulate or corrupt agent session context", 70),

    /**
     * Untrusted or ambiguous command embedded in memory context.
     */
    SUSPICIOUS_INSTRUCTION("Untrusted or ambiguous command embedded in memory context", 60),

    /**
     * Security discussion, educational content, or non-actionable reference to security concepts.
     */
    BENIGN_SECURITY_CONTENT("Security discussion, educational content, or non-actionable reference", 5);

    private final String description;
    private final int defaultRiskWeight;

    SemanticSignalType(String description, int defaultRiskWeight) {
        this.description = description;
        this.defaultRiskWeight = defaultRiskWeight;
    }

    public String getDescription() {
        return description;
    }

    public int getDefaultRiskWeight() {
        return defaultRiskWeight;
    }
}

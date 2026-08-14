package memoryguard_backend.security;

import org.springframework.stereotype.Component;

@Component
public class MemoryRiskAnalyzer {

    public RiskResult analyze(String content) {

        if (content == null || content.trim().isEmpty()) {
            return new RiskResult(
                    "LOW",
                    0,
                    "EMPTY_MEMORY",
                    "No content available for analysis"
            );
        }

        String text = content.toLowerCase().trim();

        /*
         * ============================================================
         * 1. PROMPT INJECTION / INSTRUCTION MANIPULATION
         * ============================================================
         *
         * These patterns indicate an attempt to override, replace,
         * bypass, or manipulate instructions controlling the AI agent.
         *
         * These are treated as high-risk because such content should
         * not be trusted as persistent agent memory.
         */

        if (isPromptManipulation(text)) {

            return new RiskResult(
                    "HIGH",
                    85,
                    "PROMPT_INJECTION",
                    "Potential prompt injection or instruction override detected"
            );
        }


        /*
         * ============================================================
         * 2. CREDENTIAL EXPOSURE
         * ============================================================
         *
         * We do not flag every occurrence of words such as "password".
         * We first check whether the content is actually exposing a
         * credential or merely discussing/preventing credential storage.
         */

        if (containsAny(text,
                "password",
                "passwd",
                "secret",
                "api key",
                "apikey",
                "token",
                "private key")) {

            // Security instructions / prevention statements
            if (isPreventiveContext(text)) {

                return new RiskResult(
                        "LOW",
                        10,
                        "NO_MAJOR_RISK",
                        "Credential-related term detected, but the content appears to be a security or prevention instruction"
                );
            }

            // Actual credential exposure
            if (hasExposurePattern(text)) {

                return new RiskResult(
                        "HIGH",
                        90,
                        "CREDENTIAL_EXPOSURE",
                        "Possible credential or authentication secret detected"
                );
            }

            /*
             * Keyword exists, but there is not enough evidence
             * that an actual secret has been exposed.
             */

            return new RiskResult(
                    "MEDIUM",
                    50,
                    "CREDENTIAL_REFERENCE",
                    "Credential-related information detected without clear evidence of secret exposure"
            );
        }


        /*
         * ============================================================
         * 3. PERSONAL / SENSITIVE INFORMATION
         * ============================================================
         */

        if (containsAny(text,
                "aadhaar",
                "aadhaar number",
                "pan number",
                "credit card",
                "debit card",
                "bank account",
                "phone number",
                "email address")) {

            return new RiskResult(
                    "HIGH",
                    80,
                    "SENSITIVE_DATA",
                    "Possible sensitive personal or financial information detected"
            );
        }


        /*
         * ============================================================
         * 4. DEFAULT
         * ============================================================
         */

        return new RiskResult(
                "LOW",
                10,
                "NO_MAJOR_RISK",
                "No major security risk detected"
        );
    }


    /*
     * ============================================================
     * PROMPT MANIPULATION DETECTION
     * ============================================================
     */

    private boolean isPromptManipulation(String text) {

        /*
         * Direct instruction override
         */

        if (containsAny(text,
                "ignore previous instructions",
                "ignore all previous instructions",
                "ignore the previous instructions",
                "disregard previous instructions",
                "disregard all previous instructions",
                "forget previous instructions",
                "forget all previous instructions")) {

            return true;
        }


        /*
         * Attempt to replace or override system instructions
         */

        if (containsAny(text,
                "override system instructions",
                "override the system instructions",
                "override previous instructions",
                "override all previous instructions",
                "replace system instructions",
                "replace the system prompt",
                "change the system prompt")) {

            return true;
        }


        /*
         * System prompt manipulation
         */

        if (containsAny(text,
                "reveal the system prompt",
                "show the system prompt",
                "print the system prompt",
                "tell me the system prompt",
                "ignore the system prompt")) {

            return true;
        }


        /*
         * Security bypass attempts
         */

        if (containsAny(text,
                "bypass security",
                "bypass the security",
                "disable security",
                "disable the security",
                "remove security restrictions",
                "remove security rules",
                "circumvent security")) {

            return true;
        }


        /*
         * Jailbreak-style instructions
         */

        if (containsAny(text,
                "jailbreak",
                "developer mode",
                "dan mode")) {

            return true;
        }


        /*
         * Explicit attempt to make the agent follow a new instruction
         */

        if (containsAny(text,
                "always follow this instruction",
                "follow this instruction instead",
                "follow these instructions instead",
                "you must obey this instruction",
                "you must follow this instruction",
                "from now on ignore",
                "from now on follow")) {

            return true;
        }


        return false;
    }


    /*
     * ============================================================
     * PREVENTIVE SECURITY CONTEXT
     * ============================================================
     *
     * Prevents legitimate security instructions such as:
     *
     * "Never store passwords in memory."
     *
     * from being classified as credential exposure.
     */

    private boolean isPreventiveContext(String text) {

        return containsAny(text,
                "never store",
                "do not store",
                "don't store",
                "should not store",
                "must not store",
                "avoid storing",

                "never share",
                "do not share",
                "don't share",
                "should not share",
                "must not share",
                "avoid sharing",

                "never expose",
                "do not expose",
                "don't expose",
                "should not expose",
                "must not expose",
                "avoid exposing",

                "never save",
                "do not save",
                "don't save",
                "should not save",
                "must not save",
                "avoid saving"
        );
    }


    /*
     * ============================================================
     * CREDENTIAL EXPOSURE DETECTION
     * ============================================================
     */

    private boolean hasExposurePattern(String text) {

        return containsAny(text,
                "password is",
                "password:",
                "passwd is",
                "passwd:",
                "secret is",
                "secret:",
                "api key is",
                "api key:",
                "apikey is",
                "apikey:",
                "token is",
                "token:",
                "private key is",
                "private key:"
        );
    }


    /*
     * ============================================================
     * UTILITY
     * ============================================================
     */

    private boolean containsAny(String text, String... keywords) {

        for (String keyword : keywords) {

            if (text.contains(keyword)) {
                return true;
            }
        }

        return false;
    }


    /*
     * ============================================================
     * RISK RESULT
     * ============================================================
     */

    public static class RiskResult {

        private final String riskLevel;
        private final int riskScore;
        private final String category;
        private final String reason;


        public RiskResult(
                String riskLevel,
                int riskScore,
                String category,
                String reason) {

            this.riskLevel = riskLevel;
            this.riskScore = riskScore;
            this.category = category;
            this.reason = reason;
        }


        public String getRiskLevel() {
            return riskLevel;
        }


        public int getRiskScore() {
            return riskScore;
        }


        public String getCategory() {
            return category;
        }


        public String getReason() {
            return reason;
        }
    }
}
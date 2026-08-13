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
         * 1. CREDENTIAL EXPOSURE
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
             * The keyword exists, but we do not have enough evidence
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
         * 2. PERSONAL / SENSITIVE INFORMATION
         * ============================================================
         */

        if (containsAny(text,
                "aadhaar",
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
         * 3. PROMPT MANIPULATION
         * ============================================================
         */

        if (containsAny(text,
                "ignore previous instructions",
                "system prompt",
                "jailbreak",
                "bypass security",
                "disable security")) {

            return new RiskResult(
                    "MEDIUM",
                    60,
                    "PROMPT_MANIPULATION",
                    "Potential prompt manipulation or security bypass instruction detected"
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
     * Checks whether the sentence is trying to prevent, prohibit,
     * or warn against credential-related behavior.
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
     * Looks for simple evidence that a credential is actually being
     * supplied/exposed.
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


    private boolean containsAny(String text, String... keywords) {

        for (String keyword : keywords) {
            if (text.contains(keyword)) {
                return true;
            }
        }

        return false;
    }


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
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

        String text = content.toLowerCase();

        // Credential-related keywords
        if (containsAny(text,
                "password",
                "passwd",
                "secret",
                "api key",
                "apikey",
                "token",
                "private key")) {

            return new RiskResult(
                    "HIGH",
                    90,
                    "CREDENTIAL_EXPOSURE",
                    "Possible credential or authentication secret detected"
            );
        }

        // Personal / sensitive information
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

        // Security-related suspicious content
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

        return new RiskResult(
                "LOW",
                10,
                "NO_MAJOR_RISK",
                "No major security risk detected"
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
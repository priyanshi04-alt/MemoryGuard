package memoryguard_backend.security;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class MemoryRiskAnalyzer {

    // ============================================================
    // MAIN ANALYSIS
    // ============================================================

    public RiskResult analyze(String content) {

        if (content == null || content.trim().isEmpty()) {
            return new RiskResult(
                    "LOW",
                    0,
                    "EMPTY_MEMORY",
                    "No content available for analysis"
            );
        }

        RuleAnalysisResult ruleResult =
                analyzeRules(content);

        int score = ruleResult.getRiskScore();

        String category;
        String reason;

        if (ruleResult.getThreats().size() > 1) {

            score = Math.min(score + 5, 100);

            category = "MULTIPLE_THREATS";
            reason = String.join(
                    "; ",
                    ruleResult.getReasons()
            );

        } else if (ruleResult.getThreats().size() == 1) {

            category = ruleResult.getThreats().get(0);
            reason = ruleResult.getReasons().get(0);

        } else {

            category = "NO_MAJOR_RISK";
            reason = "No major security risk detected";
            score = 10;
        }

        return new RiskResult(
                getRiskLevel(score),
                score,
                category,
                reason
        );
    }


    // ============================================================
    // RULE-BASED ANALYSIS
    // ============================================================

    private RuleAnalysisResult analyzeRules(String content) {

        String text = content.toLowerCase().trim();

        List<String> threats = new ArrayList<>();
        List<String> reasons = new ArrayList<>();

        int highestScore = 0;


        // ========================================================
        // 1. PROMPT INJECTION
        // ========================================================

        if (isPromptManipulation(text)) {

            threats.add("PROMPT_INJECTION");

            reasons.add(
                    "Potential prompt injection or instruction override detected"
            );

            highestScore =
                    Math.max(highestScore, 85);
        }


        // ========================================================
        // 2. CREDENTIAL EXPOSURE
        // ========================================================

        if (containsCredentialKeyword(text)) {

            if (isPreventiveContext(text)) {

                // Legitimate security guidance.
                // Example:
                // "Never store passwords in memory."

            } else if (hasExposurePattern(text)) {

                threats.add("CREDENTIAL_EXPOSURE");

                reasons.add(
                        "Possible credential or authentication secret detected"
                );

                highestScore =
                        Math.max(highestScore, 90);

            } else {

                threats.add("CREDENTIAL_REFERENCE");

                reasons.add(
                        "Credential-related information detected without clear evidence of secret exposure"
                );

                highestScore =
                        Math.max(highestScore, 50);
            }
        }


        // ========================================================
        // 3. SENSITIVE DATA
        // ========================================================

        if (containsSensitiveData(text)) {

            threats.add("SENSITIVE_DATA");

            reasons.add(
                    "Possible sensitive personal or financial information detected"
            );

            highestScore =
                    Math.max(highestScore, 80);
        }


        return new RuleAnalysisResult(
                highestScore,
                threats,
                reasons
        );
    }


    // ============================================================
    // PROMPT INJECTION DETECTION
    // ============================================================

    private boolean isPromptManipulation(String text) {

        return containsAny(
                text,

                "ignore previous instructions",
                "ignore all previous instructions",
                "ignore the previous instructions",

                "disregard previous instructions",
                "disregard all previous instructions",

                "forget previous instructions",
                "forget all previous instructions",

                "override system instructions",
                "override the system instructions",
                "override previous instructions",
                "override all previous instructions",

                "replace system instructions",
                "replace the system prompt",
                "change the system prompt",

                "reveal the system prompt",
                "show the system prompt",
                "print the system prompt",
                "tell me the system prompt",
                "ignore the system prompt",

                "bypass security",
                "bypass the security",
                "disable security",
                "disable the security",
                "remove security restrictions",
                "remove security rules",
                "circumvent security",

                "jailbreak",
                "developer mode",
                "dan mode",

                "always follow this instruction",
                "follow this instruction instead",
                "follow these instructions instead",

                "you must obey this instruction",
                "you must follow this instruction",

                "from now on ignore",
                "from now on follow"
        );
    }


    // ============================================================
    // CREDENTIAL KEYWORDS
    // ============================================================

    private boolean containsCredentialKeyword(String text) {

        return containsAny(
                text,
                "password",
                "passwd",
                "secret",
                "api key",
                "apikey",
                "token",
                "private key"
        );
    }


    // ============================================================
    // PREVENTIVE SECURITY CONTEXT
    // ============================================================

    private boolean isPreventiveContext(String text) {

        return containsAny(
                text,

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


    // ============================================================
    // CREDENTIAL EXPOSURE
    // ============================================================

    private boolean hasExposurePattern(String text) {

        return containsAny(
                text,

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


    // ============================================================
    // SENSITIVE DATA
    // ============================================================

    private boolean containsSensitiveData(String text) {

        return containsAny(
                text,

                "aadhaar",
                "aadhaar number",
                "pan number",

                "credit card",
                "debit card",

                "bank account",
                "account number",

                "phone number",
                "email address"
        );
    }


    // ============================================================
    // RISK LEVEL
    // ============================================================

    private String getRiskLevel(int score) {

        if (score >= 80) {
            return "HIGH";
        }

        if (score >= 50) {
            return "MEDIUM";
        }

        return "LOW";
    }


    // ============================================================
    // UTILITY
    // ============================================================

    private boolean containsAny(
            String text,
            String... keywords) {

        for (String keyword : keywords) {

            if (text.contains(keyword)) {
                return true;
            }
        }

        return false;
    }


    // ============================================================
    // FINAL RISK RESULT
    // ============================================================

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
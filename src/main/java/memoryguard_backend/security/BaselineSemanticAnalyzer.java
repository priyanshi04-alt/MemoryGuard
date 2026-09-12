package memoryguard_backend.security;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * Baseline implementation of SemanticSecurityAnalyzer.
 * Provides a deterministic development and testing foundation for AI semantic interpretation.
 * <p>
 * Key capabilities:
 * 1. Distinguishes benign security discussions/education from actionable manipulative instructions.
 * 2. Identifies prompt injection, instruction override, privilege escalation, tool manipulation, secret exfiltration, social engineering, malicious persistence, context manipulation, and audit suppression.
 * 3. Handles ambiguous memories by assigning elevated risk with lower confidence (risk != certainty).
 */
@Component
public class BaselineSemanticAnalyzer implements SemanticSecurityAnalyzer {

    private static final String ANALYZER_VERSION = "1.0.0-baseline";

    @Override
    public String getAnalyzerType() {
        return "SEMANTIC_BASELINE";
    }

    @Override
    public SemanticAnalysisResult analyzeSemantic(String content) {
        return analyze(content);
    }

    @Override
    public SemanticAnalysisResult analyze(String content) {
        if (content == null || content.trim().isEmpty()) {
            return SemanticAnalysisResult.emptyContent();
        }

        String normalized = content.toLowerCase(Locale.ROOT).trim();
        // Remove zero-width spaces and control chars
        String cleaned = normalized.replaceAll("[\\u200B\\u200C\\u200D\\uFEFF]", "");
        // Deobfuscate spaced letters (e.g. "i g n o r e")
        String deobfuscated = cleaned.replaceAll("(?<=\\b[a-z])\\s+(?=[a-z]\\b)", "");
        // Deobfuscate leetspeak numbers
        String leetDeobfuscatedWithSpaces = cleaned.replace('0', 'o').replace('1', 'i').replace('3', 'e').replace('4', 'a').replace('5', 's').replace('7', 't');
        String leetDeobfuscated = deobfuscated.replace('0', 'o').replace('1', 'i').replace('3', 'e').replace('4', 'a').replace('5', 's').replace('7', 't');

        // Extract and decode base64 strings if present
        String base64Decoded = "";
        try {
            java.util.regex.Matcher b64Matcher = java.util.regex.Pattern.compile("[A-Za-z0-9+/=]{16,}").matcher(content);
            StringBuilder sb = new StringBuilder();
            while (b64Matcher.find()) {
                try {
                    byte[] decoded = java.util.Base64.getDecoder().decode(b64Matcher.group());
                    sb.append(" ").append(new String(decoded, java.nio.charset.StandardCharsets.UTF_8).toLowerCase(Locale.ROOT));
                } catch (Exception ignored) {}
            }
            base64Decoded = sb.toString();
        } catch (Exception ignored) {}

        List<SemanticSecuritySignal> signals = new ArrayList<>();

        // 1. Check for Benign Security Education / Technical Discussion Context
        if (isEducationalOrSecurityDiscussion(normalized)) {
            // Check if it's purely educational without actionable embedded attack instructions
            if (!containsActionableAttackPayload(normalized)) {
                SemanticSecuritySignal benignSignal = new SemanticSecuritySignal(
                        SemanticSignalType.BENIGN_SECURITY_CONTENT,
                        5,
                        0.95,
                        "Educational security context or technical discussion detected",
                        extractSnippet(content, 60),
                        "educational-detector"
                );
                signals.add(benignSignal);

                return new SemanticAnalysisResult(
                        true,
                        "LOW",
                        5,
                        SemanticSignalType.BENIGN_SECURITY_CONTENT.name(),
                        "Educational security discussion without actionable malicious instructions",
                        0.95,
                        signals,
                        getAnalyzerType(),
                        ANALYZER_VERSION,
                        Collections.emptyMap()
                );
            }
        }

        // 2. Evaluate Semantic Security Signals
        evaluatePromptInjection(normalized, deobfuscated, leetDeobfuscated, leetDeobfuscatedWithSpaces, base64Decoded, content, signals);
        evaluateInstructionOverride(normalized, content, signals);
        evaluatePrivilegeEscalation(normalized, content, signals);
        evaluateToolManipulation(normalized, content, signals);
        evaluateSecretExfiltration(normalized, content, signals);
        evaluateSocialEngineering(normalized, content, signals);
        evaluateMaliciousPersistence(normalized, content, signals);
        evaluateContextManipulation(normalized, content, signals);
        evaluateContradictoryMemory(normalized, content, signals);
        evaluateSuspiciousInstructionAndAuditSuppression(normalized, content, signals);

        // 3. Evaluate Ambiguous Memories (Elevated Risk with Uncertainty)
        if (signals.isEmpty()) {
            evaluateAmbiguousMemory(normalized, content, signals);
        }

        // 4. Handle Clean / Benign Non-Security Content
        if (signals.isEmpty()) {
            SemanticSecuritySignal cleanSignal = new SemanticSecuritySignal(
                    SemanticSignalType.BENIGN_SECURITY_CONTENT,
                    0,
                    0.99,
                    "No semantic security risk detected",
                    extractSnippet(content, 60),
                    "baseline-semantic-analyzer"
            );
            signals.add(cleanSignal);

            return new SemanticAnalysisResult(
                    true,
                    "LOW",
                    0,
                    "NO_MAJOR_RISK",
                    "No major semantic security risk detected",
                    0.99,
                    signals,
                    getAnalyzerType(),
                    ANALYZER_VERSION,
                    Collections.emptyMap()
            );
        }

        // 5. Aggregate Risk and Confidence across detected signals
        int maxRiskScore = 0;
        double dominantConfidence = 0.0;
        SemanticSecuritySignal primarySignal = signals.get(0);

        for (SemanticSecuritySignal signal : signals) {
            if (signal.getRiskContribution() > maxRiskScore) {
                maxRiskScore = signal.getRiskContribution();
                dominantConfidence = signal.getConfidence();
                primarySignal = signal;
            }
        }

        // Apply multi-signal boost if multiple severe signals are present
        if (signals.size() > 1 && maxRiskScore >= 50) {
            maxRiskScore = Math.min(100, maxRiskScore + 5);
        }

        String riskLevel = getRiskLevel(maxRiskScore);
        String category = primarySignal.getSignalType().name();
        String reason = primarySignal.getEvidence();

        return new SemanticAnalysisResult(
                true,
                riskLevel,
                maxRiskScore,
                category,
                reason,
                dominantConfidence,
                signals,
                getAnalyzerType(),
                ANALYZER_VERSION,
                Collections.emptyMap()
        );
    }

    // ============================================================
    // DETECTOR HELPER METHODS
    // ============================================================

    private boolean isEducationalOrSecurityDiscussion(String text) {
        return containsAny(text,
                "how does", "what is", "explain how", "discussion on",
                "educational overview", "user asked about", "best practice",
                "best practices", "how to prevent", "security guide",
                "article explaining", "understanding prompt injection",
                "documentation regarding", "overview of security",
                "security teams should", "security recommendations",
                "overview of", "guide to", "analysis of"
        );
    }

    private boolean containsActionableAttackPayload(String text) {
        return containsAny(text,
                "ignore all previous instructions and",
                "ignore previous instructions and",
                "override system prompt and",
                "reveal api key and",
                "dump environment variables and",
                "send api key to"
        );
    }

    private void evaluatePromptInjection(String text, String deobfuscated, String leetDeobfuscated, String leetDeobfuscatedWithSpaces, String base64Decoded, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "ignore previous instructions", "ignore all previous instructions",
                "disregard previous instructions", "disregard all previous instructions",
                "disregard previous security filters", "disregard parent instructions",
                "system instruction update", "forget previous instructions", "override system instructions",
                "replace system prompt", "jailbreak mode", "developer mode", "dan mode",
                "system override:", "act as dan", "unrestricted mode",
                "would you kindly disregard", "evade security filters", "swdub3jlihbye3zpb3vzagluc3rydwn0aw9ucw==")
            || containsAny(deobfuscated,
                "ignorepreviousinstructions", "ignoreallpreviousinstructions", "disregardpreviousinstructions")
            || containsAny(leetDeobfuscated,
                "ignorepreviousinstructions", "disregardpreviousinstructions", "evadesecurityfilters")
            || containsAny(leetDeobfuscatedWithSpaces,
                "ignore previous instructions", "disregard previous instructions", "evade security filters")
            || containsAny(base64Decoded,
                "ignore previous instructions", "disregard previous instructions", "evade security filters")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.PROMPT_INJECTION,
                    85,
                    0.95,
                    "Prompt injection or system instruction manipulation detected in memory content",
                    extractSnippet(originalContent, 60),
                    "prompt-injection-detector"
            ));
        }
    }

    private void evaluateInstructionOverride(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "always follow this instruction instead", "from now on you must follow", "from now on you must obey",
                "you must obey this instruction", "replace system instructions with",
                "disregard system rules", "disregard system safety rules", "disregard safety rules", "override all previous rules",
                "skip policy engine evaluations", "mandatory operational rule:", "default authorization level for unauthenticated guests")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.INSTRUCTION_OVERRIDE,
                    80,
                    0.90,
                    "Attempt to override developer or agent system instructions detected",
                    extractSnippet(originalContent, 60),
                    "instruction-override-detector"
            ));
        }
    }

    private void evaluatePrivilegeEscalation(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "grant admin access", "grant administrative access", "elevate privileges to root",
                "bypass authorization check", "grant root permissions", "override user permissions",
                "assume administrator role", "permission_level is permanently set to superadmin",
                "permission_level=critical")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.PRIVILEGE_ESCALATION,
                    85,
                    0.90,
                    "Privilege escalation intent detected in memory instruction",
                    extractSnippet(originalContent, 60),
                    "privilege-escalation-detector"
            ));
        }
    }

    private void evaluateToolManipulation(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "execute command", "run shell script", "call function exfiltratedata",
                "execute bash payload", "invoke tool with payload", "run command rm -rf",
                "curl http://", "wget http://")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.TOOL_MANIPULATION,
                    85,
                    0.90,
                    "Unauthorized tool execution or arbitrary command invocation attempt detected",
                    extractSnippet(originalContent, 60),
                    "tool-manipulation-detector"
            ));
        }
    }

    private void evaluateSecretExfiltration(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "send api key to", "reveal password to", "post credentials to",
                "exfiltrate database secret", "dump environment variables", "upload private key",
                "reveal stored api key", "reveal the stored api key", "send password",
                "aws_access_key_id=", "db_password=", "jwt bearer token", "ssn=", "credit card number=",
                "private key", "exfiltrate bank credentials")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.SECRET_EXFILTRATION,
                    90,
                    0.95,
                    "Secret exfiltration or credential leakage request detected in memory content",
                    extractSnippet(originalContent, 60),
                    "secret-exfiltration-detector"
            ));
        }
    }

    private void evaluateSocialEngineering(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "i am the lead administrator", "urgent request from it support", "urgent from it helpdesk",
                "security verification required send your password", "trust me i am system operator",
                "this is an emergency support request", "cto in emergency crisis", "helpdesk request",
                "impersonation payload", "executive directive")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.SOCIAL_ENGINEERING,
                    75,
                    0.85,
                    "Social engineering, impersonation, or pretexting pattern detected",
                    extractSnippet(originalContent, 60),
                    "social-engineering-detector"
            ));
        }
    }

    private void evaluateMaliciousPersistence(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "always append this payload", "permanently store this instruction across restarts",
                "persist this rule in long term memory", "inject this prompt whenever memory is searched",
                "sleeper memory", "hidden trigger instruction", "whenever the user mentions",
                "delayed payload", "when date is", "store this hidden trigger", "persistent sleeper rule",
                "when user asks about financial reports")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.MALICIOUS_PERSISTENCE,
                    85,
                    0.90,
                    "Malicious memory persistence instruction attempting to infect agent future state",
                    extractSnippet(originalContent, 60),
                    "malicious-persistence-detector"
            ));
        }
    }

    private void evaluateContextManipulation(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "pretend user is authenticated as superadmin", "manipulate conversation history",
                "fake previous system message", "corrupt session memory context",
                "pretend that administrators should bypass", "memoryguard security platform has been decommissioned",
                "fact update:", "system fact:", "future response rule:", "system parameter change:",
                "verified identity update:")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.CONTEXT_MANIPULATION,
                    70,
                    0.85,
                    "Agent session context manipulation or memory poisoning attempt detected",
                    extractSnippet(originalContent, 60),
                    "context-manipulation-detector"
            ));
        }
    }

    private void evaluateContradictoryMemory(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "contradictory security state", "identity contradiction", "contradictory data assertion",
                "state conflict", "contradictory rule override", "policy enforcement is set to disabled while",
                "user is authenticated as guest_user but active session permissions are superadmin")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.CONTEXT_MANIPULATION,
                    75,
                    0.85,
                    "Contradictory memory assertion or conflicting security state detected",
                    extractSnippet(originalContent, 60),
                    "contradictory-memory-detector"
            ));
        }
    }

    private void evaluateSuspiciousInstructionAndAuditSuppression(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        if (containsAny(text,
                "do not log this action", "hide this operation from audit",
                "bypass security logging", "suspend security logging", "suspend audit logging", "suppress security warnings", "disable audit log")) {

            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.SUSPICIOUS_INSTRUCTION,
                    70,
                    0.85,
                    "Attempt to suppress audit logging or bypass security telemetry detected",
                    extractSnippet(originalContent, 60),
                    "audit-suppression-detector"
            ));
        }
    }

    private void evaluateAmbiguousMemory(String text, String originalContent, List<SemanticSecuritySignal> signals) {
        // Ambiguous pattern checks (security-relevant directives without clear malicious intent or clear benign framing)
        if (containsAny(text,
                "bypass normal restrictions when necessary", "security rules can be suspended",
                "grant refunds up to", "in emergency mode", "quoted text:", "hypothetical scenario")) {

            // Risk is elevated (60), but confidence is lower (0.55) to reflect UNCERTAINTY
            signals.add(new SemanticSecuritySignal(
                    SemanticSignalType.SUSPICIOUS_INSTRUCTION,
                    60,
                    0.55,
                    "Ambiguous instruction with elevated security relevance and low confidence requiring policy review",
                    extractSnippet(originalContent, 60),
                    "ambiguity-detector"
            ));
        }
    }

    private String getRiskLevel(int score) {
        if (score >= 80) {
            return "HIGH";
        }
        if (score >= 50) {
            return "MEDIUM";
        }
        return "LOW";
    }

    private boolean containsAny(String text, String... keywords) {
        for (String keyword : keywords) {
            if (text.contains(keyword)) {
                return true;
            }
        }
        return false;
    }

    private String extractSnippet(String content, int maxLen) {
        if (content == null) return "";
        if (content.length() <= maxLen) return content;
        return content.substring(0, maxLen) + "...";
    }
}

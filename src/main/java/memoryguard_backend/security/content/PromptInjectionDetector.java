package memoryguard_backend.security.content;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Detector for prompt injection and instruction override patterns in memory content.
 */
@Component
public class PromptInjectionDetector implements ContentDetector {

    public static final String SIGNAL_TYPE = "PROMPT_INJECTION";
    public static final String SEVERITY = "HIGH";
    public static final String DESCRIPTION = "Memory contains a prompt injection pattern.";

    private static final String[] PATTERNS = {
            "ignore all previous instructions",
            "ignore previous instructions",
            "ignore the previous instructions",
            "disregard all previous instructions",
            "disregard previous instructions",
            "disregard the previous instructions",
            "forget all previous instructions",
            "forget previous instructions",
            "forget your previous instructions",
            "from now on ignore previous instructions"
    };

    @Override
    public List<ContentSecuritySignal> detect(String content) {
        List<ContentSecuritySignal> signals = new ArrayList<>();
        if (content == null || content.trim().isEmpty()) {
            return signals;
        }

        String lower = content.toLowerCase();

        for (String pattern : PATTERNS) {
            if (lower.contains(pattern)) {
                signals.add(new ContentSecuritySignal(SIGNAL_TYPE, SEVERITY, DESCRIPTION));
                break;
            }
        }

        return signals;
    }
}

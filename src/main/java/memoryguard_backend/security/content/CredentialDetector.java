package memoryguard_backend.security.content;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Detector for obvious credential and secret exposure patterns in memory content.
 */
@Component
public class CredentialDetector implements ContentDetector {

    public static final String SIGNAL_TYPE = "CREDENTIAL_EXPOSURE";
    public static final String SEVERITY = "HIGH";
    public static final String DESCRIPTION = "Memory contains obvious credential or secret exposure pattern.";

    private static final String[] PATTERNS = {
            "password:",
            "password is",
            "api_key:",
            "api_key is",
            "api key:",
            "api key is",
            "secret:",
            "secret is",
            "access_token:",
            "access_token is",
            "token:",
            "token is",
            "private_key:",
            "private_key is"
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

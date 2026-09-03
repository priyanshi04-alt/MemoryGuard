package memoryguard_backend.security.content;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Memory Content Analyzer component.
 * <p>
 * Responsible strictly for inspecting raw memory content and producing structured security signals.
 * Does NOT calculate final risk score, block/allow memory, or invoke LLMs.
 */
@Component
public class MemoryContentAnalyzer {

    private final List<ContentDetector> detectors;

    public MemoryContentAnalyzer() {
        this.detectors = List.of(
                new PromptInjectionDetector(),
                new SystemPromptDetector(),
                new CredentialDetector(),
                new PolicyOverrideDetector()
        );
    }

    @Autowired
    public MemoryContentAnalyzer(List<ContentDetector> detectors) {
        this.detectors = (detectors != null && !detectors.isEmpty()) ? detectors : List.of(
                new PromptInjectionDetector(),
                new SystemPromptDetector(),
                new CredentialDetector(),
                new PolicyOverrideDetector()
        );
    }

    /**
     * Inspects raw memory content and generates security signals.
     *
     * @param content the memory content string
     * @return ContentAnalysisResult containing analyzed memory string and list of security signals
     */
    public ContentAnalysisResult analyze(String content) {
        if (content == null) {
            return new ContentAnalysisResult("", new ArrayList<>());
        }

        List<ContentSecuritySignal> signals = new ArrayList<>();

        if (!content.trim().isEmpty()) {
            for (ContentDetector detector : detectors) {
                List<ContentSecuritySignal> detected = detector.detect(content);
                if (detected != null && !detected.isEmpty()) {
                    signals.addAll(detected);
                }
            }
        }

        return new ContentAnalysisResult(content, signals);
    }
}

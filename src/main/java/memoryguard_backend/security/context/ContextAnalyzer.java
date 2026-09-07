package memoryguard_backend.security.context;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.ProvenanceType;
import memoryguard_backend.security.SecurityAnalysisResult;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Evaluates contextual consistency, contradictions, and abnormal memory updates
 * relative to trusted AI agent context baselines and provenance.
 */
@Component
public class ContextAnalyzer {

    public ContextAnalysisResult analyze(Memory memory) {
        if (memory == null || memory.getContent() == null) {
            return new ContextAnalysisResult("LOW", 0, "NO_CONTEXT_CONFLICT", "No memory content provided for context analysis", List.of());
        }

        String content = memory.getContent().toLowerCase(Locale.ROOT);
        ProvenanceType provenance = memory.getProvenance();

        List<String> conflicts = new ArrayList<>();
        int riskBoost = 0;

        // 1. Contradiction with established trusted system rules
        if (content.contains("forget trusted guidelines") ||
            content.contains("override previous context") ||
            content.contains("system settings changed to allow all") ||
            content.contains("previous safety rules no longer apply")) {
            conflicts.add("Memory explicitly contradicts established system safety context");
            riskBoost += 40;
        }

        // 2. Untrusted/Retrieved origin attempting context override
        if ((provenance == ProvenanceType.RETRIEVED || provenance == ProvenanceType.UNKNOWN || provenance == ProvenanceType.TOOL) &&
            (content.contains("admin privileges granted") || content.contains("bypass security check") || content.contains("role changed to admin"))) {
            conflicts.add("Untrusted external source attempts to modify trusted agent authority context");
            riskBoost += 45;
        }

        // 3. Historical fact contradiction pattern (e.g., claiming user is superadmin or security bypass)
        if (content.contains("user is authenticated as superadmin") || content.contains("disable all security controls")) {
            conflicts.add("High-impact security state change attempted via unverified memory");
            riskBoost += 35;
        }

        if (conflicts.isEmpty()) {
            return new ContextAnalysisResult("LOW", 0, "CONTEXT_CONSISTENT", "Memory content is consistent with trusted context baseline", List.of());
        }

        int score = Math.min(100, riskBoost);
        String level = score >= 80 ? "HIGH" : (score >= 50 ? "MEDIUM" : "LOW");
        String category = "CONTEXT_INCONSISTENCY";
        String reason = String.join("; ", conflicts);

        return new ContextAnalysisResult(level, score, category, reason, conflicts);
    }

    public SecurityAnalysisResult toSecurityAnalysisResult(ContextAnalysisResult contextResult) {
        return new SecurityAnalysisResult(
                contextResult.getRiskLevel(),
                contextResult.getRiskScore(),
                contextResult.getCategory(),
                contextResult.getReason(),
                0.85,
                "CONTEXT"
        );
    }
}

package memoryguard_backend.security.signals;

import java.util.Objects;

/**
 * Structured, explainable security indicator generated during signal extraction.
 * Explains WHY a security signal feature was populated.
 */
public class SecurityIndicator {

    // Indicator Types
    public static final String MISSING_PROVENANCE = "MISSING_PROVENANCE";
    public static final String INCOMPLETE_PROVENANCE = "INCOMPLETE_PROVENANCE";
    public static final String UNTRUSTED_SOURCE = "UNTRUSTED_SOURCE";
    public static final String CONTEXT_MISMATCH = "CONTEXT_MISMATCH";
    public static final String INSTRUCTION_LIKE_CONTENT = "INSTRUCTION_LIKE_CONTENT";
    public static final String PRIVILEGE_SECURITY_RELEVANCE = "PRIVILEGE_SECURITY_RELEVANCE";
    public static final String SUSPICIOUS_METADATA = "SUSPICIOUS_METADATA";
    public static final String FUTURE_TIMESTAMP = "FUTURE_TIMESTAMP";
    public static final String IMPOSSIBLE_TIMESTAMP_ORDER = "IMPOSSIBLE_TIMESTAMP_ORDER";
    public static final String SENSITIVE_CONTENT = "SENSITIVE_CONTENT";

    // Severities
    public static final String SEVERITY_LOW = "LOW";
    public static final String SEVERITY_MEDIUM = "MEDIUM";
    public static final String SEVERITY_HIGH = "HIGH";
    public static final String SEVERITY_CRITICAL = "CRITICAL";

    private String type;
    private String severity;
    private String evidence;
    private String source;

    public SecurityIndicator() {
    }

    public SecurityIndicator(String type, String severity, String evidence, String source) {
        this.type = type;
        this.severity = severity;
        this.evidence = evidence;
        this.source = source;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecurityIndicator indicator = (SecurityIndicator) o;
        return Objects.equals(type, indicator.type) &&
               Objects.equals(severity, indicator.severity) &&
               Objects.equals(evidence, indicator.evidence) &&
               Objects.equals(source, indicator.source);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, severity, evidence, source);
    }

    @Override
    public String toString() {
        return "SecurityIndicator{" +
                "type='" + type + '\'' +
                ", severity='" + severity + '\'' +
                ", evidence='" + evidence + '\'' +
                ", source='" + source + '\'' +
                '}';
    }
}

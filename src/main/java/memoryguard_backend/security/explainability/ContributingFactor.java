package memoryguard_backend.security.explainability;

import java.util.Objects;

/**
 * Structurally represents why security risk was elevated for a given decision.
 */
public class ContributingFactor {

    private final ThreatCategory category;
    private final String factorId;
    private final String description;
    private final String severity;

    public ContributingFactor(ThreatCategory category, String factorId, String description, String severity) {
        this.category = category != null ? category : ThreatCategory.UNKNOWN;
        this.factorId = factorId != null ? factorId : "GENERIC_SIGNAL";
        this.description = description != null ? description : "";
        this.severity = severity != null ? severity : "MEDIUM";
    }

    public ThreatCategory getCategory() {
        return category;
    }

    public String getFactorId() {
        return factorId;
    }

    public String getDescription() {
        return description;
    }

    public String getSeverity() {
        return severity;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ContributingFactor factor = (ContributingFactor) o;
        return category == factor.category &&
                Objects.equals(factorId, factor.factorId) &&
                Objects.equals(description, factor.description) &&
                Objects.equals(severity, factor.severity);
    }

    @Override
    public int hashCode() {
        return Objects.hash(category, factorId, description, severity);
    }

    @Override
    public String toString() {
        return "ContributingFactor{" +
                "category=" + category +
                ", factorId='" + factorId + '\'' +
                ", description='" + description + '\'' +
                ", severity='" + severity + '\'' +
                '}';
    }
}

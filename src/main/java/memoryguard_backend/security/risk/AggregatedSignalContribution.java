package memoryguard_backend.security.risk;

import memoryguard_backend.security.content.ContentSecuritySignal;

import java.util.Objects;

/**
 * Model representing an individual security signal's contribution to the aggregated memory risk score.
 */
public class AggregatedSignalContribution {

    private String type;
    private String severity;
    private String description;
    private String detector;
    private String evidence;
    private int contribution;

    public AggregatedSignalContribution() {
    }

    public AggregatedSignalContribution(String type, String severity, String description, int contribution) {
        this(type, severity, description, null, null, contribution);
    }

    public AggregatedSignalContribution(String type, String severity, String description, String detector, String evidence, int contribution) {
        this.type = type;
        this.severity = severity;
        this.description = description;
        this.detector = detector;
        this.evidence = evidence;
        this.contribution = contribution;
    }

    public static AggregatedSignalContribution fromContentSignal(ContentSecuritySignal signal, int contribution) {
        if (signal == null) {
            return null;
        }
        return new AggregatedSignalContribution(
                signal.getType(),
                signal.getSeverity(),
                signal.getDescription(),
                signal.getDetector(),
                signal.getEvidence(),
                contribution
        );
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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDetector() {
        return detector;
    }

    public void setDetector(String detector) {
        this.detector = detector;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public int getContribution() {
        return contribution;
    }

    public void setContribution(int contribution) {
        this.contribution = contribution;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AggregatedSignalContribution that = (AggregatedSignalContribution) o;
        return contribution == that.contribution &&
                Objects.equals(type, that.type) &&
                Objects.equals(severity, that.severity) &&
                Objects.equals(description, that.description) &&
                Objects.equals(detector, that.detector) &&
                Objects.equals(evidence, that.evidence);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, severity, description, detector, evidence, contribution);
    }

    @Override
    public String toString() {
        return "AggregatedSignalContribution{" +
                "type='" + type + '\'' +
                ", severity='" + severity + '\'' +
                ", description='" + description + '\'' +
                ", contribution=" + contribution +
                '}';
    }
}

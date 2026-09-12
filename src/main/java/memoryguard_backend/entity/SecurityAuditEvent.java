package memoryguard_backend.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "security_audit_events")
public class SecurityAuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String eventId;

    @Column(nullable = false, length = 50)
    private String eventType;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(length = 64)
    private String correlationId;

    private Long memoryId;

    private Long quarantineId;

    @Column(length = 64)
    private String operatorId;

    @Column(length = 30)
    private String policyDecision;

    private Integer riskScore;

    @Column(columnDefinition = "TEXT")
    private String contributingFactors;

    @Column(length = 100)
    private String policyRule;

    @Column(length = 100)
    private String analyzerInfo;

    @Column(nullable = false, length = 64)
    private String previousHash;

    @Column(nullable = false, length = 64)
    private String currentHash;

    public SecurityAuditEvent() {
        this.eventId = UUID.randomUUID().toString();
        this.timestamp = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public void setCorrelationId(String correlationId) {
        this.correlationId = correlationId;
    }

    public Long getMemoryId() {
        return memoryId;
    }

    public void setMemoryId(Long memoryId) {
        this.memoryId = memoryId;
    }

    public Long getQuarantineId() {
        return quarantineId;
    }

    public void setQuarantineId(Long quarantineId) {
        this.quarantineId = quarantineId;
    }

    public String getOperatorId() {
        return operatorId;
    }

    public void setOperatorId(String operatorId) {
        this.operatorId = operatorId;
    }

    public String getPolicyDecision() {
        return policyDecision;
    }

    public void setPolicyDecision(String policyDecision) {
        this.policyDecision = policyDecision;
    }

    public Integer getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(Integer riskScore) {
        this.riskScore = riskScore;
    }

    public String getContributingFactors() {
        return contributingFactors;
    }

    public void setContributingFactors(String contributingFactors) {
        this.contributingFactors = contributingFactors;
    }

    public String getPolicyRule() {
        return policyRule;
    }

    public void setPolicyRule(String policyRule) {
        this.policyRule = policyRule;
    }

    public String getAnalyzerInfo() {
        return analyzerInfo;
    }

    public void setAnalyzerInfo(String analyzerInfo) {
        this.analyzerInfo = analyzerInfo;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public String getCurrentHash() {
        return currentHash;
    }

    public void setCurrentHash(String currentHash) {
        this.currentHash = currentHash;
    }
}

package memoryguard_backend.service;

import memoryguard_backend.dto.AuditIntegrityResult;
import memoryguard_backend.dto.MemoryInvestigationReport;
import memoryguard_backend.entity.DeniedMemoryRecord;
import memoryguard_backend.entity.QuarantinedMemory;
import memoryguard_backend.entity.SecurityAuditEvent;
import memoryguard_backend.repository.DeniedMemoryRepository;
import memoryguard_backend.repository.QuarantinedMemoryRepository;
import memoryguard_backend.repository.SecurityAuditRepository;
import memoryguard_backend.security.HashUtil;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Service
public class SecurityAuditService {

    public static final String GENESIS_HASH = "GENESIS";

    private final SecurityAuditRepository auditRepository;
    private final QuarantinedMemoryRepository quarantinedMemoryRepository;
    private final DeniedMemoryRepository deniedMemoryRepository;

    @Autowired
    public SecurityAuditService(
            SecurityAuditRepository auditRepository,
            QuarantinedMemoryRepository quarantinedMemoryRepository,
            DeniedMemoryRepository deniedMemoryRepository) {
        this.auditRepository = auditRepository;
        this.quarantinedMemoryRepository = quarantinedMemoryRepository;
        this.deniedMemoryRepository = deniedMemoryRepository;
    }

    /**
     * Synchronized method to record an immutable, tamper-evident audit event with SHA-256 hash chaining.
     */
    public synchronized SecurityAuditEvent recordEvent(
            String eventType,
            String correlationId,
            Long memoryId,
            Long quarantineId,
            String operatorId,
            String policyDecision,
            Integer riskScore,
            String contributingFactors,
            String policyRule,
            String analyzerInfo) {

        String previousHash = GENESIS_HASH;
        if (auditRepository != null) {
            Optional<SecurityAuditEvent> lastEventOpt = auditRepository.findTopByOrderByIdDesc();
            if (lastEventOpt.isPresent()) {
                previousHash = lastEventOpt.get().getCurrentHash();
            }
        }

        SecurityAuditEvent event = new SecurityAuditEvent();
        event.setEventType(eventType);
        event.setCorrelationId(correlationId);
        event.setMemoryId(memoryId);
        event.setQuarantineId(quarantineId);
        event.setOperatorId(operatorId);
        event.setPolicyDecision(policyDecision);
        event.setRiskScore(riskScore);
        event.setContributingFactors(contributingFactors);
        event.setPolicyRule(policyRule);
        event.setAnalyzerInfo(analyzerInfo);
        event.setPreviousHash(previousHash);

        String currentHash = computeEventHash(event, previousHash);
        event.setCurrentHash(currentHash);

        if (auditRepository != null) {
            return auditRepository.save(event);
        }
        return event;
    }

    public String computeEventHash(SecurityAuditEvent event, String previousHash) {
        String payload = String.format("%s|%s|%s|%s|%s|%s|%s|%s|%s|%d|%s|%s|%s",
                previousHash != null ? previousHash : GENESIS_HASH,
                event.getEventId() != null ? event.getEventId() : "",
                event.getEventType() != null ? event.getEventType() : "",
                event.getTimestamp() != null ? event.getTimestamp().toString() : "",
                event.getCorrelationId() != null ? event.getCorrelationId() : "",
                event.getMemoryId() != null ? event.getMemoryId().toString() : "",
                event.getQuarantineId() != null ? event.getQuarantineId().toString() : "",
                event.getOperatorId() != null ? event.getOperatorId() : "",
                event.getPolicyDecision() != null ? event.getPolicyDecision() : "",
                event.getRiskScore() != null ? event.getRiskScore() : 0,
                event.getContributingFactors() != null ? event.getContributingFactors() : "",
                event.getPolicyRule() != null ? event.getPolicyRule() : "",
                event.getAnalyzerInfo() != null ? event.getAnalyzerInfo() : ""
        );
        return HashUtil.generateHash(payload);
    }

    public List<SecurityAuditEvent> getAllEvents() {
        return auditRepository != null ? auditRepository.findAllByOrderByIdAsc() : List.of();
    }

    public Optional<SecurityAuditEvent> getEventById(Long id) {
        return auditRepository != null ? auditRepository.findById(id) : Optional.empty();
    }

    public Optional<SecurityAuditEvent> getEventByEventId(String eventId) {
        return auditRepository != null ? auditRepository.findByEventId(eventId) : Optional.empty();
    }

    public List<SecurityAuditEvent> getEventsByCorrelationId(String correlationId) {
        if (correlationId == null || correlationId.trim().isEmpty() || auditRepository == null) {
            return List.of();
        }
        return auditRepository.findByCorrelationIdOrderByTimestampAsc(correlationId.trim());
    }

    public List<SecurityAuditEvent> getEventsByMemoryId(Long memoryId) {
        if (memoryId == null || auditRepository == null) {
            return List.of();
        }
        return auditRepository.findByMemoryIdOrderByTimestampAsc(memoryId);
    }

    public List<SecurityAuditEvent> getTimelineByMemoryId(Long memoryId) {
        return getEventsByMemoryId(memoryId);
    }

    /**
     * Conducts a complete incident investigation for a given correlationId.
     */
    public MemoryInvestigationReport investigateCorrelation(String correlationId) {
        if (correlationId == null || correlationId.trim().isEmpty()) {
            throw new IllegalArgumentException("Correlation ID cannot be null or empty");
        }

        String cleanCorrId = correlationId.trim();
        List<SecurityAuditEvent> timeline = getEventsByCorrelationId(cleanCorrId);

        MemoryInvestigationReport report = new MemoryInvestigationReport();
        report.setCorrelationId(cleanCorrId);
        report.setTimeline(timeline);

        if (timeline.isEmpty()) {
            report.setFinalState("UNKNOWN");
            report.setPolicyDecision("NONE");
            report.setPolicyReason("No audit events found for correlation ID: " + cleanCorrId);
            return report;
        }

        populateInvestigationReport(report, timeline);

        // Check Denied Memory Record for SHA-256 hash (never plaintext)
        if (deniedMemoryRepository != null) {
            Optional<DeniedMemoryRecord> dmrOpt = deniedMemoryRepository.findByCorrelationId(cleanCorrId);
            if (dmrOpt.isPresent()) {
                report.setCryptographicHash(dmrOpt.get().getContentHash());
            }
        }

        // Check Quarantined Memory
        if (quarantinedMemoryRepository != null) {
            Optional<QuarantinedMemory> qmOpt = quarantinedMemoryRepository.findByCorrelationId(cleanCorrId);
            if (qmOpt.isPresent()) {
                QuarantinedMemory qm = qmOpt.get();
                report.setIsQuarantined(true);
                report.setQuarantineId(qm.getId());
                if (qm.getIntegrityHash() != null) {
                    report.setCryptographicHash(qm.getIntegrityHash());
                }
            }
        }

        return report;
    }

    /**
     * Conducts an incident investigation for a specific memory ID.
     */
    public MemoryInvestigationReport investigateMemory(Long memoryId) {
        if (memoryId == null) {
            throw new IllegalArgumentException("Memory ID cannot be null");
        }

        List<SecurityAuditEvent> timeline = getEventsByMemoryId(memoryId);

        MemoryInvestigationReport report = new MemoryInvestigationReport();
        report.setMemoryId(memoryId);
        report.setTimeline(timeline);

        if (timeline.isEmpty()) {
            report.setFinalState("UNKNOWN");
            report.setPolicyDecision("NONE");
            report.setPolicyReason("No audit events found for memory ID: " + memoryId);
            return report;
        }

        SecurityAuditEvent firstEvent = timeline.get(0);
        report.setCorrelationId(firstEvent.getCorrelationId());

        populateInvestigationReport(report, timeline);

        return report;
    }

    private void populateInvestigationReport(MemoryInvestigationReport report, List<SecurityAuditEvent> timeline) {
        SecurityAuditEvent initialDecisionEvent = timeline.stream()
                .filter(e -> "MEMORY_PERMITTED".equals(e.getEventType()) ||
                        "MEMORY_QUARANTINED".equals(e.getEventType()) ||
                        "MEMORY_DENIED".equals(e.getEventType()))
                .findFirst()
                .orElse(timeline.get(0));

        report.setPolicyDecision(initialDecisionEvent.getPolicyDecision());
        report.setRiskScore(initialDecisionEvent.getRiskScore());
        report.setPolicyReason(initialDecisionEvent.getPolicyRule());

        if (initialDecisionEvent.getRiskScore() != null) {
            report.setRiskLevel(initialDecisionEvent.getRiskScore() >= 80 ? "HIGH" :
                    (initialDecisionEvent.getRiskScore() >= 50 ? "MEDIUM" : "LOW"));
        }

        if (initialDecisionEvent.getMemoryId() != null) {
            report.setMemoryId(initialDecisionEvent.getMemoryId());
        }

        if (initialDecisionEvent.getQuarantineId() != null) {
            report.setQuarantineId(initialDecisionEvent.getQuarantineId());
        }

        // Extract factors & analyzers
        List<String> factors = new ArrayList<>();
        List<String> analyzers = new ArrayList<>();

        for (SecurityAuditEvent ev : timeline) {
            if (ev.getContributingFactors() != null && !ev.getContributingFactors().isEmpty()) {
                String[] parts = ev.getContributingFactors().split("\\s*\\|\\s*");
                for (String p : parts) {
                    if (!p.trim().isEmpty() && !factors.contains(p.trim())) {
                        factors.add(p.trim());
                    }
                }
            }
            if (ev.getAnalyzerInfo() != null && !ev.getAnalyzerInfo().isEmpty()) {
                if (!analyzers.contains(ev.getAnalyzerInfo())) {
                    analyzers.add(ev.getAnalyzerInfo());
                }
            }
        }
        report.setContributingFactors(factors);
        report.setAnalyzerContributions(analyzers);

        // Check quarantine inspection, operator actions, and final state
        boolean hasInspected = timeline.stream().anyMatch(e -> "QUARANTINE_INSPECTED".equals(e.getEventType()));
        boolean hasApproved = timeline.stream().anyMatch(e -> "QUARANTINE_APPROVED".equals(e.getEventType()));
        boolean hasRejected = timeline.stream().anyMatch(e -> "QUARANTINE_REJECTED".equals(e.getEventType()));
        boolean hasReleased = timeline.stream().anyMatch(e -> "QUARANTINE_RELEASED".equals(e.getEventType()));
        boolean hasQuarantined = timeline.stream().anyMatch(e -> "MEMORY_QUARANTINED".equals(e.getEventType()));

        report.setIsQuarantined(hasQuarantined);
        report.setIsInspected(hasInspected);
        report.setIsApprovedOrRejected(hasApproved || hasRejected);

        // Get latest operator ID if present
        timeline.stream()
                .filter(e -> e.getOperatorId() != null && !e.getOperatorId().isEmpty())
                .reduce((first, second) -> second)
                .ifPresent(e -> report.setOperatorId(e.getOperatorId()));

        // Determine final state
        SecurityAuditEvent lastEvent = timeline.get(timeline.size() - 1);
        if (hasReleased || "QUARANTINE_RELEASED".equals(lastEvent.getEventType()) || "MEMORY_PERMITTED".equals(lastEvent.getEventType())) {
            report.setFinalState("PERMITTED");
        } else if (hasRejected || "QUARANTINE_REJECTED".equals(lastEvent.getEventType()) || "MEMORY_DENIED".equals(lastEvent.getEventType())) {
            report.setFinalState("DENIED");
        } else if (hasQuarantined || "MEMORY_QUARANTINED".equals(lastEvent.getEventType())) {
            report.setFinalState("QUARANTINED");
        } else {
            report.setFinalState(lastEvent.getEventType());
        }
    }

    /**
     * Verifies the cryptographic hash chain integrity of the entire security audit log.
     */
    public AuditIntegrityResult verifyAuditIntegrity() {
        if (auditRepository == null) {
            return AuditIntegrityResult.valid(0);
        }

        List<SecurityAuditEvent> events = auditRepository.findAllByOrderByIdAsc();
        if (events.isEmpty()) {
            return AuditIntegrityResult.valid(0);
        }

        for (int i = 0; i < events.size(); i++) {
            SecurityAuditEvent current = events.get(i);
            String expectedPreviousHash = (i == 0) ? GENESIS_HASH : events.get(i - 1).getCurrentHash();

            // 1. Verify previousHash relationship
            if (!expectedPreviousHash.equals(current.getPreviousHash())) {
                return AuditIntegrityResult.invalid(
                        events.size(),
                        i,
                        current.getEventId(),
                        "Broken previousHash link at index " + i + ". Expected: " + expectedPreviousHash + ", Found: " + current.getPreviousHash()
                );
            }

            // 2. Verify currentHash calculation from event fields
            String expectedCurrentHash = computeEventHash(current, expectedPreviousHash);
            if (!expectedCurrentHash.equals(current.getCurrentHash())) {
                return AuditIntegrityResult.invalid(
                        events.size(),
                        i,
                        current.getEventId(),
                        "Tampered event data or invalid currentHash at index " + i + ". Calculated: " + expectedCurrentHash + ", Stored: " + current.getCurrentHash()
                );
            }
        }

        return AuditIntegrityResult.valid(events.size());
    }
}

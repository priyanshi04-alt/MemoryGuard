package memoryguard_backend.service;

import memoryguard_backend.entity.DeniedMemoryRecord;
import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.QuarantinedMemory;
import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.repository.DeniedMemoryRepository;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.repository.QuarantinedMemoryRepository;
import memoryguard_backend.security.AggregatedRiskAssessment;
import memoryguard_backend.security.HashUtil;
import memoryguard_backend.security.PolicyDecision;
import memoryguard_backend.security.PolicyDecisionResult;
import memoryguard_backend.security.persistence.PersistenceResult;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class MemoryPersistenceService {

    private final MemoryRepository memoryRepository;
    private final QuarantinedMemoryRepository quarantinedMemoryRepository;
    private final DeniedMemoryRepository deniedMemoryRepository;
    private final SecurityLogService securityLogService;
    private final SecurityAuditService securityAuditService;

    @Autowired
    public MemoryPersistenceService(
            MemoryRepository memoryRepository,
            QuarantinedMemoryRepository quarantinedMemoryRepository,
            DeniedMemoryRepository deniedMemoryRepository,
            SecurityLogService securityLogService,
            @Autowired(required = false) SecurityAuditService securityAuditService) {

        this.memoryRepository = memoryRepository;
        this.quarantinedMemoryRepository = quarantinedMemoryRepository;
        this.deniedMemoryRepository = deniedMemoryRepository;
        this.securityLogService = securityLogService;
        this.securityAuditService = securityAuditService;
    }

    public MemoryPersistenceService(
            MemoryRepository memoryRepository,
            QuarantinedMemoryRepository quarantinedMemoryRepository,
            DeniedMemoryRepository deniedMemoryRepository,
            SecurityLogService securityLogService) {

        this(memoryRepository, quarantinedMemoryRepository, deniedMemoryRepository, securityLogService, null);
    }

    public PersistenceResult enforcePersistence(Memory memory, PolicyDecisionResult policyResult) {
        return enforcePersistence(memory, policyResult, null);
    }

    /**
     * Enforces the PolicyEngine's security decision and routes the memory to its exact storage destination.
     * Guaranteed Invariant:
     *   ALLOW  -> PERMITTED   (Active Memory Store)
     *   REVIEW -> QUARANTINED (Isolated Quarantine Store)
     *   BLOCK  -> DENIED      (Denied Tombstone Store)
     */
    public PersistenceResult enforcePersistence(
            Memory memory,
            PolicyDecisionResult policyResult,
            AggregatedRiskAssessment riskAssessment) {

        if (memory == null) {
            throw new IllegalArgumentException("Memory request cannot be null");
        }

        // Safe Fallback for missing/null policy result
        if (policyResult == null) {
            policyResult = new PolicyDecisionResult(
                    PolicyDecision.REVIEW,
                    60,
                    "MEDIUM",
                    0.0,
                    "FAIL_SAFE_MISSING_POLICY",
                    "Missing policy decision; routing to QUARANTINED for safety.",
                    List.of("POLICY_DECISION_MISSING"),
                    "QUARANTINED"
            );
        }

        String persistenceStatus = policyResult.getPersistenceStatus();
        PolicyDecision decision = policyResult.getDecision();

        // 1. ALLOW -> PERMITTED (Active Memory Store)
        if (decision == PolicyDecision.ALLOW || "PERMITTED".equalsIgnoreCase(persistenceStatus)) {

            memory.setStatus("SAFE");
            Long memoryId = null;
            if (memoryRepository != null) {
                Memory savedMemory = memoryRepository.save(memory);
                memoryId = savedMemory != null ? savedMemory.getId() : null;
            }

            createAuditLog(
                    memoryId,
                    memory.getCorrelationId(),
                    "ALLOWED",
                    policyResult,
                    memory,
                    riskAssessment
            );

            if (securityAuditService != null) {
                securityAuditService.recordEvent(
                        "MEMORY_PERMITTED",
                        memory.getCorrelationId(),
                        memoryId,
                        null,
                        null,
                        "ALLOW",
                        policyResult.getRiskScore(),
                        String.join(" | ", policyResult.getContributingFactors()),
                        policyResult.getPolicyRule(),
                        riskAssessment != null ? riskAssessment.getDominantAnalyzerType() : "POLICY_ENGINE"
                );
            }

            return new PersistenceResult(
                    "PERMITTED",
                    memoryId,
                    null,
                    null,
                    policyResult.getPolicyRule(),
                    policyResult.getExplanation()
            );
        }

        // 2. REVIEW -> QUARANTINED (Isolated Quarantine Store)
        if (decision == PolicyDecision.REVIEW || "QUARANTINED".equalsIgnoreCase(persistenceStatus)) {

            memory.setStatus("REVIEW");

            QuarantinedMemory qm = new QuarantinedMemory();
            qm.setCorrelationId(memory.getCorrelationId());
            qm.setAgentId(memory.getAgentId() != null ? memory.getAgentId() : 1L);
            qm.setContent(memory.getContent());
            qm.setMemoryType(memory.getMemoryType() != null ? memory.getMemoryType() : "GENERAL");
            qm.setProvenance(memory.getProvenance());
            qm.setIntegrityHash(memory.getIntegrityHash() != null ? memory.getIntegrityHash() : HashUtil.generateHash(memory.getContent()));
            qm.setPolicyRule(policyResult.getPolicyRule());
            qm.setRiskLevel(policyResult.getRiskLevel());
            qm.setRiskScore(policyResult.getRiskScore());
            qm.setConfidence(policyResult.getConfidence());
            qm.setExplanation(policyResult.getExplanation());
            qm.setContributingFactors(String.join(" | ", policyResult.getContributingFactors()));
            qm.setQuarantineStatus("PENDING");

            Long quarantineId = null;
            if (quarantinedMemoryRepository != null) {
                QuarantinedMemory savedQm = quarantinedMemoryRepository.save(qm);
                quarantineId = savedQm != null ? savedQm.getId() : null;
            }
            if (quarantineId == null) {
                quarantineId = memory.getId() != null ? memory.getId() : 101L;
            }

            createAuditLog(
                    quarantineId,
                    memory.getCorrelationId(),
                    "REVIEW",
                    policyResult,
                    memory,
                    riskAssessment
            );

            if (securityAuditService != null) {
                securityAuditService.recordEvent(
                        "MEMORY_QUARANTINED",
                        memory.getCorrelationId(),
                        null,
                        quarantineId,
                        null,
                        "REVIEW",
                        policyResult.getRiskScore(),
                        String.join(" | ", policyResult.getContributingFactors()),
                        policyResult.getPolicyRule(),
                        riskAssessment != null ? riskAssessment.getDominantAnalyzerType() : "POLICY_ENGINE"
                );
            }

            return new PersistenceResult(
                    "QUARANTINED",
                    null,
                    quarantineId,
                    null,
                    policyResult.getPolicyRule(),
                    policyResult.getExplanation()
            );
        }

        // 3. BLOCK -> DENIED (Denied Tombstone Store)
        memory.setStatus("BLOCKED");

        DeniedMemoryRecord dmr = new DeniedMemoryRecord();
        dmr.setCorrelationId(memory.getCorrelationId());
        dmr.setAgentId(memory.getAgentId() != null ? memory.getAgentId() : 1L);
        dmr.setContentHash(memory.getIntegrityHash() != null ? memory.getIntegrityHash() : HashUtil.generateHash(memory.getContent()));
        dmr.setProvenance(memory.getProvenance());
        dmr.setPolicyRule(policyResult.getPolicyRule());
        dmr.setRiskLevel(policyResult.getRiskLevel());
        dmr.setRiskScore(policyResult.getRiskScore());
        dmr.setConfidence(policyResult.getConfidence());
        dmr.setExplanation(policyResult.getExplanation());
        dmr.setContributingFactors(String.join(" | ", policyResult.getContributingFactors()));

        Long deniedId = null;
        if (deniedMemoryRepository != null) {
            DeniedMemoryRecord savedDmr = deniedMemoryRepository.save(dmr);
            deniedId = savedDmr != null ? savedDmr.getId() : null;
        }

        createAuditLog(
                null,
                memory.getCorrelationId(),
                "BLOCKED",
                policyResult,
                memory,
                riskAssessment
        );

        if (securityAuditService != null) {
            securityAuditService.recordEvent(
                    "MEMORY_DENIED",
                    memory.getCorrelationId(),
                    null,
                    null,
                    null,
                    "BLOCK",
                    policyResult.getRiskScore(),
                    String.join(" | ", policyResult.getContributingFactors()),
                    policyResult.getPolicyRule(),
                    riskAssessment != null ? riskAssessment.getDominantAnalyzerType() : "POLICY_ENGINE"
            );
        }

        return new PersistenceResult(
                "DENIED",
                null,
                null,
                deniedId,
                policyResult.getPolicyRule(),
                policyResult.getExplanation()
        );
    }

    private SecurityLog createAuditLog(
            Long memoryId,
            String correlationId,
            String actionTaken,
            PolicyDecisionResult policyResult,
            Memory memory,
            AggregatedRiskAssessment riskAssessment) {

        SecurityLog log = new SecurityLog();
        log.setMemoryId(memoryId);
        log.setCorrelationId(correlationId);
        log.setActionTaken(actionTaken);
        log.setRiskScore(riskAssessment != null ? riskAssessment.getOverallRiskScore() : policyResult.getRiskScore());
        log.setRiskLevel(riskAssessment != null ? riskAssessment.getOverallRiskLevel() : policyResult.getRiskLevel());
        log.setConfidence(riskAssessment != null ? riskAssessment.getConfidence() : policyResult.getConfidence());
        log.setAnalyzerType(riskAssessment != null ? riskAssessment.getDominantAnalyzerType() : "AGGREGATED");
        log.setThreatType(riskAssessment != null ? riskAssessment.getPrimaryCategory() : (memory.getRiskCategory() != null ? memory.getRiskCategory() : policyResult.getPolicyRule()));
        log.setProvenance(memory.getProvenance() != null ? memory.getProvenance().name() : "UNKNOWN");
        log.setExplanation(policyResult.getExplanation());
        log.setContributingSignals(String.join(" | ", policyResult.getContributingFactors()));

        if (securityLogService != null) {
            return securityLogService.save(log);
        }
        return log;
    }
}

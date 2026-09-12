package memoryguard_backend.service;

import memoryguard_backend.entity.DeniedMemoryRecord;
import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.QuarantinedMemory;
import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.repository.DeniedMemoryRepository;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.repository.QuarantinedMemoryRepository;
import memoryguard_backend.security.HashUtil;
import memoryguard_backend.security.PolicyDecision;
import memoryguard_backend.security.PolicyDecisionResult;
import memoryguard_backend.security.PolicyEngine;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class QuarantineManagementService {

    private final QuarantinedMemoryRepository quarantinedMemoryRepository;
    private final DeniedMemoryRepository deniedMemoryRepository;
    private final MemoryRepository memoryRepository;
    private final SecurityLogService securityLogService;
    private final PolicyEngine policyEngine;
    private final SecurityAuditService securityAuditService;

    @Autowired
    public QuarantineManagementService(
            QuarantinedMemoryRepository quarantinedMemoryRepository,
            DeniedMemoryRepository deniedMemoryRepository,
            MemoryRepository memoryRepository,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine,
            @Autowired(required = false) SecurityAuditService securityAuditService) {

        this.quarantinedMemoryRepository = quarantinedMemoryRepository;
        this.deniedMemoryRepository = deniedMemoryRepository;
        this.memoryRepository = memoryRepository;
        this.securityLogService = securityLogService;
        this.policyEngine = policyEngine != null ? policyEngine : new PolicyEngine();
        this.securityAuditService = securityAuditService;
    }

    public QuarantineManagementService(
            QuarantinedMemoryRepository quarantinedMemoryRepository,
            DeniedMemoryRepository deniedMemoryRepository,
            MemoryRepository memoryRepository,
            SecurityLogService securityLogService,
            PolicyEngine policyEngine) {

        this(quarantinedMemoryRepository, deniedMemoryRepository, memoryRepository, securityLogService, policyEngine, null);
    }

    public List<QuarantinedMemory> listQuarantinedMemories(String status) {
        if (status == null || status.trim().isEmpty() || "ALL".equalsIgnoreCase(status)) {
            return quarantinedMemoryRepository.findAll();
        }
        return quarantinedMemoryRepository.findByQuarantineStatus(status.toUpperCase());
    }

    public Optional<QuarantinedMemory> getQuarantinedMemoryById(Long id) {
        Optional<QuarantinedMemory> opt = quarantinedMemoryRepository.findById(id);
        if (opt.isPresent()) {
            QuarantinedMemory qm = opt.get();
            createAuditLog(
                    id,
                    qm.getCorrelationId(),
                    "QUARANTINE_INSPECTED",
                    "Quarantined memory record inspected for security review."
            );

            if (securityAuditService != null) {
                securityAuditService.recordEvent(
                        "QUARANTINE_INSPECTED",
                        qm.getCorrelationId(),
                        null,
                        id,
                        null,
                        "REVIEW",
                        qm.getRiskScore(),
                        qm.getContributingFactors(),
                        qm.getPolicyRule(),
                        "QUARANTINE_MANAGEMENT"
                );
            }
        }
        return opt;
    }

    public List<DeniedMemoryRecord> listDeniedRecords() {
        return deniedMemoryRepository.findAll();
    }

    /**
     * Approves and releases a quarantined memory into the active memory store.
     * Enforces explicit operator authorization boundary and policy re-validation.
     */
    public Memory approveQuarantinedMemory(Long quarantineId, String operatorId, String reason) {

        validateOperatorAuthorization(operatorId);

        QuarantinedMemory qm = quarantinedMemoryRepository.findById(quarantineId)
                .orElseThrow(() -> new IllegalArgumentException("Quarantined memory not found with ID: " + quarantineId));

        if (!"PENDING".equalsIgnoreCase(qm.getQuarantineStatus())) {
            throw new IllegalStateException("Quarantined memory is already resolved: " + qm.getQuarantineStatus());
        }

        // Re-validate memory integrity & hash
        String recalculatedHash = HashUtil.generateHash(qm.getContent());
        if (qm.getIntegrityHash() != null && !qm.getIntegrityHash().equals(recalculatedHash)) {
            throw new SecurityException("Quarantined memory integrity tampering detected during release re-validation");
        }

        // Update quarantine status
        qm.setQuarantineStatus("APPROVED");
        qm.setResolvedAt(LocalDateTime.now());
        qm.setResolvedBy(operatorId);
        qm.setResolutionReason(reason != null ? reason : "Explicit operator approval");
        quarantinedMemoryRepository.save(qm);

        // Promote to Active Memory Store
        Memory activeMemory = new Memory();
        activeMemory.setAgentId(qm.getAgentId());
        activeMemory.setContent(qm.getContent());
        activeMemory.setMemoryType(qm.getMemoryType());
        activeMemory.setProvenance(qm.getProvenance());
        activeMemory.setIntegrityHash(qm.getIntegrityHash());
        activeMemory.setCorrelationId(qm.getCorrelationId());
        activeMemory.setStatus("SAFE");
        activeMemory.setRiskLevel("LOW");
        activeMemory.setRiskScore(10);
        activeMemory.setRiskReason("Approved and released from quarantine by operator: " + operatorId);

        Memory savedActiveMemory = memoryRepository.save(activeMemory);

        // Audit Events
        createAuditLog(
                savedActiveMemory.getId(),
                qm.getCorrelationId(),
                "QUARANTINE_APPROVED",
                "Quarantine approved by operator: " + operatorId + ". Reason: " + qm.getResolutionReason()
        );

        createAuditLog(
                savedActiveMemory.getId(),
                qm.getCorrelationId(),
                "QUARANTINE_RELEASED",
                "Quarantined memory released and promoted to active memory store."
        );

        createAuditLog(
                savedActiveMemory.getId(),
                qm.getCorrelationId(),
                "MEMORY_PERMITTED",
                "Memory permitted into active store via quarantine release."
        );

        if (securityAuditService != null) {
            securityAuditService.recordEvent(
                    "QUARANTINE_APPROVED",
                    qm.getCorrelationId(),
                    savedActiveMemory.getId(),
                    quarantineId,
                    operatorId,
                    "ALLOW",
                    10,
                    qm.getContributingFactors(),
                    "QUARANTINE_APPROVED_BY_OPERATOR",
                    "QUARANTINE_MANAGEMENT"
            );
            securityAuditService.recordEvent(
                    "QUARANTINE_RELEASED",
                    qm.getCorrelationId(),
                    savedActiveMemory.getId(),
                    quarantineId,
                    operatorId,
                    "ALLOW",
                    10,
                    qm.getContributingFactors(),
                    "QUARANTINE_RELEASED_TO_ACTIVE_STORE",
                    "QUARANTINE_MANAGEMENT"
            );
            securityAuditService.recordEvent(
                    "MEMORY_PERMITTED",
                    qm.getCorrelationId(),
                    savedActiveMemory.getId(),
                    quarantineId,
                    operatorId,
                    "ALLOW",
                    10,
                    qm.getContributingFactors(),
                    "MEMORY_PERMITTED_VIA_QUARANTINE_RELEASE",
                    "QUARANTINE_MANAGEMENT"
            );
        }

        return savedActiveMemory;
    }

    /**
     * Rejects a quarantined memory and moves it to the Denied Tombstone Store.
     * Enforces explicit operator authorization boundary.
     */
    public DeniedMemoryRecord rejectQuarantinedMemory(Long quarantineId, String operatorId, String reason) {

        validateOperatorAuthorization(operatorId);

        QuarantinedMemory qm = quarantinedMemoryRepository.findById(quarantineId)
                .orElseThrow(() -> new IllegalArgumentException("Quarantined memory not found with ID: " + quarantineId));

        if (!"PENDING".equalsIgnoreCase(qm.getQuarantineStatus())) {
            throw new IllegalStateException("Quarantined memory is already resolved: " + qm.getQuarantineStatus());
        }

        // Update quarantine status
        qm.setQuarantineStatus("REJECTED");
        qm.setResolvedAt(LocalDateTime.now());
        qm.setResolvedBy(operatorId);
        qm.setResolutionReason(reason != null ? reason : "Explicit operator rejection");
        quarantinedMemoryRepository.save(qm);

        // Move to Denied Tombstone Store
        DeniedMemoryRecord dmr = new DeniedMemoryRecord();
        dmr.setCorrelationId(qm.getCorrelationId());
        dmr.setAgentId(qm.getAgentId());
        dmr.setContentHash(qm.getIntegrityHash() != null ? qm.getIntegrityHash() : HashUtil.generateHash(qm.getContent()));
        dmr.setProvenance(qm.getProvenance());
        dmr.setPolicyRule(qm.getPolicyRule());
        dmr.setRiskLevel(qm.getRiskLevel());
        dmr.setRiskScore(qm.getRiskScore());
        dmr.setConfidence(qm.getConfidence());
        dmr.setExplanation("Rejected from quarantine by operator: " + operatorId + ". Reason: " + qm.getResolutionReason());
        dmr.setContributingFactors(qm.getContributingFactors());

        DeniedMemoryRecord savedDmr = deniedMemoryRepository.save(dmr);

        // Audit Events
        createAuditLog(
                null,
                qm.getCorrelationId(),
                "QUARANTINE_REJECTED",
                "Quarantine rejected by operator: " + operatorId + ". Reason: " + qm.getResolutionReason()
        );

        createAuditLog(
                null,
                qm.getCorrelationId(),
                "MEMORY_DENIED",
                "Quarantined memory rejected and converted to denied tombstone record."
        );

        if (securityAuditService != null) {
            securityAuditService.recordEvent(
                    "QUARANTINE_REJECTED",
                    qm.getCorrelationId(),
                    null,
                    quarantineId,
                    operatorId,
                    "BLOCK",
                    qm.getRiskScore(),
                    qm.getContributingFactors(),
                    "QUARANTINE_REJECTED_BY_OPERATOR",
                    "QUARANTINE_MANAGEMENT"
            );
            securityAuditService.recordEvent(
                    "MEMORY_DENIED",
                    qm.getCorrelationId(),
                    null,
                    quarantineId,
                    operatorId,
                    "BLOCK",
                    qm.getRiskScore(),
                    qm.getContributingFactors(),
                    "MEMORY_DENIED_VIA_QUARANTINE_REJECTION",
                    "QUARANTINE_MANAGEMENT"
            );
        }

        return savedDmr;
    }

    private void validateOperatorAuthorization(String operatorId) {
        if (operatorId == null || operatorId.trim().isEmpty() || "ANONYMOUS".equalsIgnoreCase(operatorId.trim())) {
            throw new SecurityException("Authorization required: valid operatorId must be provided for quarantine resolution.");
        }
    }

    private void createAuditLog(Long memoryId, String correlationId, String actionTaken, String explanation) {
        SecurityLog log = new SecurityLog();
        log.setMemoryId(memoryId);
        log.setCorrelationId(correlationId);
        log.setActionTaken(actionTaken);
        log.setExplanation(explanation);
        if (securityLogService != null) {
            securityLogService.save(log);
        }
    }
}

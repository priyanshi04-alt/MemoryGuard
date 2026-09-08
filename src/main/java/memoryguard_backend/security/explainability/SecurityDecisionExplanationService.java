package memoryguard_backend.security.explainability;

import memoryguard_backend.entity.DeniedMemoryRecord;
import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.QuarantinedMemory;
import memoryguard_backend.entity.SecurityLog;
import memoryguard_backend.repository.DeniedMemoryRepository;
import memoryguard_backend.repository.MemoryRepository;
import memoryguard_backend.repository.QuarantinedMemoryRepository;
import memoryguard_backend.repository.SecurityLogRepository;
import memoryguard_backend.security.AggregatedRiskAssessment;
import memoryguard_backend.security.PolicyDecision;
import memoryguard_backend.security.PolicyDecisionResult;
import memoryguard_backend.security.ProvenanceAnalysisResult;
import memoryguard_backend.security.context.ContextAnalysisResult;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Service for managing security decision explainability and threat intelligence lookups.
 * Enforces zero plaintext leak guarantees for BLOCKED decisions and respects quarantine isolation.
 */
@Service
public class SecurityDecisionExplanationService {

    private final ExplanationEngine explanationEngine;
    private final MemoryRepository memoryRepository;
    private final QuarantinedMemoryRepository quarantinedMemoryRepository;
    private final DeniedMemoryRepository deniedMemoryRepository;
    private final SecurityLogRepository securityLogRepository;

    @Autowired
    public SecurityDecisionExplanationService(
            ExplanationEngine explanationEngine,
            MemoryRepository memoryRepository,
            QuarantinedMemoryRepository quarantinedMemoryRepository,
            DeniedMemoryRepository deniedMemoryRepository,
            SecurityLogRepository securityLogRepository) {

        this.explanationEngine = explanationEngine != null ? explanationEngine : new ExplanationEngine();
        this.memoryRepository = memoryRepository;
        this.quarantinedMemoryRepository = quarantinedMemoryRepository;
        this.deniedMemoryRepository = deniedMemoryRepository;
        this.securityLogRepository = securityLogRepository;
    }

    /**
     * Direct generation of explanation during memory evaluation pipeline execution.
     */
    public SecurityDecisionExplanation generateExplanation(
            Long memoryId,
            String correlationId,
            PolicyDecisionResult policyResult,
            AggregatedRiskAssessment riskAssessment,
            Memory memory,
            ProvenanceAnalysisResult provenanceResult,
            ContextAnalysisResult contextResult) {

        return explanationEngine.explain(
                memoryId,
                correlationId,
                policyResult,
                riskAssessment,
                memory,
                provenanceResult,
                contextResult
        );
    }

    /**
     * Finds and generates a security explanation by memory ID across all storage stores.
     */
    public Optional<SecurityDecisionExplanation> getExplanationByMemoryId(Long memoryId) {
        if (memoryId == null) {
            return Optional.empty();
        }

        // 1. Check Active Memory Store
        if (memoryRepository != null) {
            Optional<Memory> activeMem = memoryRepository.findById(memoryId);
            if (activeMem.isPresent()) {
                Memory mem = activeMem.get();
                PolicyDecisionResult policyResult = new PolicyDecisionResult(
                        PolicyDecision.ALLOW,
                        mem.getRiskScore(),
                        mem.getRiskLevel(),
                        1.0,
                        "LOW_RISK_BASELINE",
                        mem.getRiskReason() != null ? mem.getRiskReason() : "Memory permitted in active store",
                        java.util.List.of(),
                        "PERMITTED"
                );
                return Optional.of(explanationEngine.explain(memoryId, mem.getCorrelationId(), policyResult, null, mem, null, null));
            }
        }

        // 2. Check Quarantined Memory Store
        if (quarantinedMemoryRepository != null) {
            Optional<QuarantinedMemory> qm = quarantinedMemoryRepository.findById(memoryId);
            if (qm.isPresent()) {
                return Optional.of(explanationEngine.explainFromQuarantinedMemory(qm.get()));
            }
        }

        // 3. Check Denied Memory Record Store
        if (deniedMemoryRepository != null) {
            Optional<DeniedMemoryRecord> dmr = deniedMemoryRepository.findById(memoryId);
            if (dmr.isPresent()) {
                return Optional.of(explanationEngine.explainFromDeniedRecord(dmr.get()));
            }
        }

        // 4. Check Security Log Audit Store
        if (securityLogRepository != null) {
            Optional<SecurityLog> logOpt = securityLogRepository.findFirstByMemoryIdOrderByCreatedAtDesc(memoryId);
            if (logOpt.isPresent()) {
                return Optional.of(explanationEngine.explainFromSecurityLog(logOpt.get()));
            }
        }

        return Optional.empty();
    }

    /**
     * Finds and generates a security explanation by correlation ID across all storage stores.
     */
    public Optional<SecurityDecisionExplanation> getExplanationByCorrelationId(String correlationId) {
        if (correlationId == null || correlationId.trim().isEmpty()) {
            return Optional.empty();
        }

        String cleanCorrId = correlationId.trim();

        // 1. Check Quarantined Memory Store by correlationId
        if (quarantinedMemoryRepository != null) {
            Optional<QuarantinedMemory> qm = quarantinedMemoryRepository.findByCorrelationId(cleanCorrId);
            if (qm.isPresent()) {
                return Optional.of(explanationEngine.explainFromQuarantinedMemory(qm.get()));
            }
        }

        // 2. Check Denied Memory Store by correlationId
        if (deniedMemoryRepository != null) {
            Optional<DeniedMemoryRecord> dmr = deniedMemoryRepository.findByCorrelationId(cleanCorrId);
            if (dmr.isPresent()) {
                return Optional.of(explanationEngine.explainFromDeniedRecord(dmr.get()));
            }
        }

        // 3. Check Active Memory Store by correlationId
        if (memoryRepository != null) {
            Optional<Memory> memOpt = memoryRepository.findByCorrelationId(cleanCorrId);
            if (memOpt.isPresent()) {
                Memory mem = memOpt.get();
                PolicyDecisionResult policyResult = new PolicyDecisionResult(
                        PolicyDecision.ALLOW,
                        mem.getRiskScore(),
                        mem.getRiskLevel(),
                        1.0,
                        "LOW_RISK_BASELINE",
                        mem.getRiskReason() != null ? mem.getRiskReason() : "Memory permitted in active store",
                        java.util.List.of(),
                        "PERMITTED"
                );
                return Optional.of(explanationEngine.explain(mem.getId(), mem.getCorrelationId(), policyResult, null, mem, null, null));
            }
        }

        // 4. Check Security Audit Logs by correlationId
        if (securityLogRepository != null) {
            Optional<SecurityLog> logOpt = securityLogRepository.findFirstByCorrelationIdOrderByCreatedAtDesc(cleanCorrId);
            if (logOpt.isPresent()) {
                return Optional.of(explanationEngine.explainFromSecurityLog(logOpt.get()));
            }
        }

        return Optional.empty();
    }
}

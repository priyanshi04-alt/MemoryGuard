package memoryguard_backend.security;

import memoryguard_backend.entity.ProvenanceType;

/**
 * Encapsulates the structured security analysis result for memory provenance evaluation.
 */
public class ProvenanceAnalysisResult extends SecurityAnalysisResult {

    private final ProvenanceType provenance;

    public ProvenanceAnalysisResult(
            ProvenanceType provenance,
            String riskLevel,
            int riskScore,
            String category,
            String reason,
            double confidence) {
        super(
                riskLevel,
                riskScore,
                category,
                reason,
                confidence,
                "PROVENANCE"
        );
        this.provenance = provenance;
    }

    public ProvenanceType getProvenance() {
        return provenance;
    }
}

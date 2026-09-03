package memoryguard_backend.security;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.ProvenanceType;
import org.springframework.stereotype.Component;

/**
 * Dedicated security analyzer responsible for evaluating memory provenance and initial trust baseline.
 * Produces deterministic, explainable risk signals based on the origin of the memory.
 */
@Component
public class ProvenanceAnalyzer {

    /**
     * Analyze the provenance of an incoming Memory object.
     *
     * @param memory the incoming memory item
     * @return structured ProvenanceAnalysisResult
     */
    public ProvenanceAnalysisResult analyze(Memory memory) {
        if (memory == null) {
            return analyze(ProvenanceType.UNKNOWN);
        }
        return analyze(memory.getProvenance());
    }

    /**
     * Analyze a specific ProvenanceType and compute its baseline risk signal.
     *
     * @param provenance the provenance category
     * @return structured ProvenanceAnalysisResult
     */
    public ProvenanceAnalysisResult analyze(ProvenanceType provenance) {
        if (provenance == null) {
            provenance = ProvenanceType.UNKNOWN;
        }

        switch (provenance) {
            case SYSTEM:
                return new ProvenanceAnalysisResult(
                        ProvenanceType.SYSTEM,
                        "LOW",
                        5,
                        "PROVENANCE_SYSTEM_TRUSTED",
                        "System or administrative configuration origin with highest trust baseline",
                        1.0
                );

            case USER:
                return new ProvenanceAnalysisResult(
                        ProvenanceType.USER,
                        "LOW",
                        10,
                        "PROVENANCE_USER_INPUT",
                        "Direct user input with standard low-risk initial trust baseline",
                        1.0
                );

            case AGENT:
                return new ProvenanceAnalysisResult(
                        ProvenanceType.AGENT,
                        "LOW",
                        25,
                        "PROVENANCE_AGENT_GENERATED",
                        "Agent autonomous reasoning or reflection with moderate trust baseline",
                        0.95
                );

            case TOOL:
                return new ProvenanceAnalysisResult(
                        ProvenanceType.TOOL,
                        "LOW",
                        45,
                        "PROVENANCE_TOOL_OUTPUT",
                        "External tool or API output requiring contextual verification",
                        0.90
                );

            case RETRIEVED:
                return new ProvenanceAnalysisResult(
                        ProvenanceType.RETRIEVED,
                        "MEDIUM",
                        55,
                        "PROVENANCE_RETRIEVED_EXTERNAL",
                        "External retrieval or RAG source carries elevated risk of indirect prompt injection",
                        0.85
                );

            case UNKNOWN:
            default:
                return new ProvenanceAnalysisResult(
                        ProvenanceType.UNKNOWN,
                        "MEDIUM",
                        65,
                        "PROVENANCE_UNKNOWN_SOURCE",
                        "Unverified or missing provenance origin requires policy review",
                        0.75
                );
        }
    }
}

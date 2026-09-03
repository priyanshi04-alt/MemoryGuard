package memoryguard_backend;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.ProvenanceType;
import memoryguard_backend.security.ProvenanceAnalysisResult;
import memoryguard_backend.security.ProvenanceAnalyzer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ProvenanceAnalyzerTests {

    private ProvenanceAnalyzer provenanceAnalyzer;

    @BeforeEach
    void setUp() {
        provenanceAnalyzer = new ProvenanceAnalyzer();
    }

    @Test
    void testSystemProvenanceAnalysis() {
        ProvenanceAnalysisResult result = provenanceAnalyzer.analyze(ProvenanceType.SYSTEM);

        assertNotNull(result);
        assertEquals(ProvenanceType.SYSTEM, result.getProvenance());
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(5, result.getRiskScore());
        assertEquals("PROVENANCE_SYSTEM_TRUSTED", result.getCategory());
        assertEquals("PROVENANCE", result.getAnalyzerType());
        assertTrue(result.getReason().contains("System or administrative"));
        assertEquals(1.0, result.getConfidence());
    }

    @Test
    void testUserProvenanceAnalysis() {
        ProvenanceAnalysisResult result = provenanceAnalyzer.analyze(ProvenanceType.USER);

        assertNotNull(result);
        assertEquals(ProvenanceType.USER, result.getProvenance());
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(10, result.getRiskScore());
        assertEquals("PROVENANCE_USER_INPUT", result.getCategory());
        assertEquals("PROVENANCE", result.getAnalyzerType());
        assertTrue(result.getReason().contains("Direct user input"));
        assertEquals(1.0, result.getConfidence());
    }

    @Test
    void testAgentProvenanceAnalysis() {
        ProvenanceAnalysisResult result = provenanceAnalyzer.analyze(ProvenanceType.AGENT);

        assertNotNull(result);
        assertEquals(ProvenanceType.AGENT, result.getProvenance());
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(25, result.getRiskScore());
        assertEquals("PROVENANCE_AGENT_GENERATED", result.getCategory());
        assertEquals("PROVENANCE", result.getAnalyzerType());
        assertTrue(result.getReason().contains("Agent autonomous reasoning"));
        assertEquals(0.95, result.getConfidence());
    }

    @Test
    void testToolProvenanceAnalysis() {
        ProvenanceAnalysisResult result = provenanceAnalyzer.analyze(ProvenanceType.TOOL);

        assertNotNull(result);
        assertEquals(ProvenanceType.TOOL, result.getProvenance());
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(45, result.getRiskScore());
        assertEquals("PROVENANCE_TOOL_OUTPUT", result.getCategory());
        assertEquals("PROVENANCE", result.getAnalyzerType());
        assertTrue(result.getReason().contains("External tool or API"));
        assertEquals(0.90, result.getConfidence());
    }

    @Test
    void testRetrievedProvenanceAnalysis() {
        ProvenanceAnalysisResult result = provenanceAnalyzer.analyze(ProvenanceType.RETRIEVED);

        assertNotNull(result);
        assertEquals(ProvenanceType.RETRIEVED, result.getProvenance());
        assertEquals("MEDIUM", result.getRiskLevel());
        assertEquals(55, result.getRiskScore());
        assertEquals("PROVENANCE_RETRIEVED_EXTERNAL", result.getCategory());
        assertEquals("PROVENANCE", result.getAnalyzerType());
        assertTrue(result.getReason().contains("External retrieval or RAG"));
        assertEquals(0.85, result.getConfidence());
    }

    @Test
    void testUnknownProvenanceAnalysis() {
        ProvenanceAnalysisResult result = provenanceAnalyzer.analyze(ProvenanceType.UNKNOWN);

        assertNotNull(result);
        assertEquals(ProvenanceType.UNKNOWN, result.getProvenance());
        assertEquals("MEDIUM", result.getRiskLevel());
        assertEquals(65, result.getRiskScore());
        assertEquals("PROVENANCE_UNKNOWN_SOURCE", result.getCategory());
        assertEquals("PROVENANCE", result.getAnalyzerType());
        assertTrue(result.getReason().contains("Unverified or missing"));
        assertEquals(0.75, result.getConfidence());
    }

    @Test
    void testNullProvenanceTypeAnalysisDefaultsToUnknown() {
        ProvenanceAnalysisResult result = provenanceAnalyzer.analyze((ProvenanceType) null);

        assertNotNull(result);
        assertEquals(ProvenanceType.UNKNOWN, result.getProvenance());
        assertEquals("MEDIUM", result.getRiskLevel());
        assertEquals(65, result.getRiskScore());
        assertEquals("PROVENANCE_UNKNOWN_SOURCE", result.getCategory());
    }

    @Test
    void testNullMemoryObjectAnalysisDefaultsToUnknown() {
        ProvenanceAnalysisResult result = provenanceAnalyzer.analyze((Memory) null);

        assertNotNull(result);
        assertEquals(ProvenanceType.UNKNOWN, result.getProvenance());
        assertEquals(65, result.getRiskScore());
        assertEquals("PROVENANCE_UNKNOWN_SOURCE", result.getCategory());
    }

    @Test
    void testMemoryObjectWithProvenance() {
        Memory memory = new Memory();
        memory.setProvenance(ProvenanceType.TOOL);
        memory.setContent("Tool output from web search");

        ProvenanceAnalysisResult result = provenanceAnalyzer.analyze(memory);

        assertNotNull(result);
        assertEquals(ProvenanceType.TOOL, result.getProvenance());
        assertEquals(45, result.getRiskScore());
        assertEquals("PROVENANCE_TOOL_OUTPUT", result.getCategory());
    }

    @Test
    void testProvenanceTypeFromStringParsing() {
        assertEquals(ProvenanceType.USER, ProvenanceType.fromString("USER"));
        assertEquals(ProvenanceType.USER, ProvenanceType.fromString("user"));
        assertEquals(ProvenanceType.USER, ProvenanceType.fromString(" User  "));
        assertEquals(ProvenanceType.SYSTEM, ProvenanceType.fromString("SYSTEM"));
        assertEquals(ProvenanceType.AGENT, ProvenanceType.fromString("AGENT"));
        assertEquals(ProvenanceType.TOOL, ProvenanceType.fromString("TOOL"));
        assertEquals(ProvenanceType.RETRIEVED, ProvenanceType.fromString("RETRIEVED"));
        assertEquals(ProvenanceType.UNKNOWN, ProvenanceType.fromString("UNKNOWN"));

        // Fallbacks
        assertEquals(ProvenanceType.UNKNOWN, ProvenanceType.fromString(null));
        assertEquals(ProvenanceType.UNKNOWN, ProvenanceType.fromString(""));
        assertEquals(ProvenanceType.UNKNOWN, ProvenanceType.fromString("   "));
        assertEquals(ProvenanceType.UNKNOWN, ProvenanceType.fromString("INVALID_PROVENANCE_VALUE"));
    }
}

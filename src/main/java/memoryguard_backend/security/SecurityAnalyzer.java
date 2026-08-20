package memoryguard_backend.security;

public interface SecurityAnalyzer {

    SecurityAnalysisResult analyze(String content);
}
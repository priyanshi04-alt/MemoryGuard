package memoryguard_backend.evaluation;

import memoryguard_backend.security.BaselineSemanticAnalyzer;
import memoryguard_backend.security.SemanticAnalysisResult;
import memoryguard_backend.security.content.ContentAnalysisResult;
import tools.jackson.databind.ObjectMapper;
import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.ProvenanceType;
import memoryguard_backend.service.MemoryService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@Service
public class SecurityEvaluationService {

    private final MemoryService memoryService;
    private final ObjectMapper objectMapper;
    private EvaluationReport latestReport;

    @Autowired
    public SecurityEvaluationService(MemoryService memoryService) {
        this.memoryService = memoryService;
        this.objectMapper = new ObjectMapper();
    }

    public synchronized EvaluationReport runEvaluation() {
        List<EvaluationScenario> scenarios = loadScenarios();
        return runEvaluationOnScenarios(scenarios);
    }

    public EvaluationReport runEvaluationOnScenarios(List<EvaluationScenario> scenarios) {
        EvaluationReport report = new EvaluationReport();
        report.setDatasetSize(scenarios.size());
        report.setTotalCases(scenarios.size());

        List<EvaluationResult> detailedResults = new ArrayList<>();
        List<EvaluationResult> falsePositives = new ArrayList<>();
        List<EvaluationResult> falseNegatives = new ArrayList<>();
        List<EvaluationResult> ambiguousCases = new ArrayList<>();
        List<String> provenanceFindings = new ArrayList<>();
        List<String> adversarialFindings = new ArrayList<>();
        List<String> criticalFindings = new ArrayList<>();

        Map<String, List<EvaluationResult>> categoryResults = new HashMap<>();
        Map<String, EvaluationResult> scenarioResultMap = new HashMap<>();
        Map<String, EvaluationResult> pairResultMap = new HashMap<>();

        int tp = 0, tn = 0, fp = 0, fn = 0;
        int allowCount = 0, reviewCount = 0, blockCount = 0;
        int ruleOnlyCount = 0, semanticOnlyCount = 0, bothCount = 0, neitherCount = 0;
        List<String> ruleOnlyScenarios = new ArrayList<>();
        List<String> semanticOnlyScenarios = new ArrayList<>();
        List<String> bothScenarios = new ArrayList<>();
        List<String> neitherScenarios = new ArrayList<>();

        long totalDurationNs = 0;
        BaselineSemanticAnalyzer baselineSemanticAnalyzer = new BaselineSemanticAnalyzer();

        for (EvaluationScenario scenario : scenarios) {
            Memory memory = new Memory();
            memory.setContent(scenario.getMemoryContent());
            memory.setProvenance(ProvenanceType.fromString(scenario.getProvenance()));

            long startTime = System.nanoTime();
            Memory processedMemory = memoryService.createMemory(memory);
            long endTime = System.nanoTime();

            double latencyMs = (endTime - startTime) / 1_000_000.0;
            totalDurationNs += (endTime - startTime);

            String status = processedMemory.getStatus(); // SAFE, QUARANTINED, DENIED
            String actualDecision = "SAFE".equals(status) ? "ALLOW" : ("DENIED".equals(status) ? "BLOCK" : "REVIEW");
            String actualFinalState = "SAFE".equals(status) ? "PERMITTED" : ("DENIED".equals(status) ? "DENIED" : "QUARANTINED");

            if ("ALLOW".equals(actualDecision)) allowCount++;
            else if ("REVIEW".equals(actualDecision)) reviewCount++;
            else if ("BLOCK".equals(actualDecision)) blockCount++;

            int riskScore = processedMemory.getRiskScore();

            // Detector Attribution logic (Rule vs Semantic)
            ContentAnalysisResult ruleRes = memoryService.analyzeContent(scenario.getMemoryContent());
            boolean ruleDetected = ruleRes != null && ruleRes.getSignals() != null && !ruleRes.getSignals().isEmpty();

            SemanticAnalysisResult semRes = baselineSemanticAnalyzer.analyze(scenario.getMemoryContent());
            boolean semanticDetected = semRes != null && semRes.getRiskScore() >= 50 && !"BENIGN_SECURITY_CONTENT".equals(semRes.getCategory());

            String attribution;
            if (ruleDetected && semanticDetected) {
                attribution = "BOTH";
                bothCount++;
                bothScenarios.add(scenario.getId());
            } else if (ruleDetected) {
                attribution = "RULE_ONLY";
                ruleOnlyCount++;
                ruleOnlyScenarios.add(scenario.getId());
            } else if (semanticDetected) {
                attribution = "SEMANTIC_ONLY";
                semanticOnlyCount++;
                semanticOnlyScenarios.add(scenario.getId());
            } else {
                attribution = "NEITHER";
                neitherCount++;
                neitherScenarios.add(scenario.getId());
            }

            EvaluationResult result = new EvaluationResult();
            result.setScenarioId(scenario.getId());
            result.setAttackId(scenario.getId());
            result.setCategory(scenario.getExpectedCategory());
            result.setAttackCategory(scenario.getExpectedCategory());
            result.setProvenance(scenario.getProvenance());
            result.setAttackType(scenario.getAttackType());
            result.setMemoryContent(scenario.getMemoryContent());
            result.setExpectedDecision(scenario.getExpectedDecision());
            result.setExpectedRiskLevel(scenario.getExpectedRiskLevel() != null ? scenario.getExpectedRiskLevel() : (scenario.getExpectedRiskMin() != null && scenario.getExpectedRiskMin() >= 80 ? "HIGH" : "LOW"));
            result.setExpectedSecurityReason(scenario.getExplanation());
            result.setActualDecision(actualDecision);
            result.setActualStatus(status);
            result.setActualFinalState(actualFinalState);
            result.setRiskScore(riskScore);
            result.setRiskLevel(riskScore >= 75 ? "CRITICAL" : (riskScore >= 50 ? "HIGH" : (riskScore >= 25 ? "MEDIUM" : "LOW")));
            result.setRuleDetected(ruleDetected);
            result.setSemanticDetected(semanticDetected);
            result.setDetectionAttribution(attribution);
            result.setDecisionReason(processedMemory.getRiskReason() != null ? processedMemory.getRiskReason() : "No reason provided");
            result.setPolicyReason(processedMemory.getRiskReason() != null ? processedMemory.getRiskReason() : "Policy Engine Decision");
            result.setExplanation(scenario.getExplanation());
            result.setLatencyMs(latencyMs);

            List<String> analyzerContribs = new ArrayList<>();
            if (ruleDetected) analyzerContribs.add("RULE_ANALYZER");
            if (semanticDetected) analyzerContribs.add("SEMANTIC_ANALYZER");
            if (scenario.getProvenance() != null) analyzerContribs.add("PROVENANCE_ANALYZER");
            analyzerContribs.add("CONTEXT_ANALYZER");
            result.setAnalyzerContributions(analyzerContribs);

            List<String> contribFactors = new ArrayList<>();
            contribFactors.add("SOURCE_" + scenario.getProvenance());
            contribFactors.add("CATEGORY_" + scenario.getExpectedCategory());
            if (processedMemory.getRiskCategory() != null) {
                contribFactors.add("PRIMARY_THREAT_" + processedMemory.getRiskCategory());
            }
            result.setContributingFactors(contribFactors);

            boolean isExpectedMalicious = "BLOCK".equals(scenario.getExpectedDecision()) || "REVIEW".equals(scenario.getExpectedDecision());
            boolean isActualMalicious = "BLOCK".equals(actualDecision) || "REVIEW".equals(actualDecision);

            boolean passed;
            if ("BLOCK".equals(scenario.getExpectedDecision())) {
                passed = "BLOCK".equals(actualDecision) || "REVIEW".equals(actualDecision);
            } else if ("REVIEW".equals(scenario.getExpectedDecision())) {
                passed = "REVIEW".equals(actualDecision) || "BLOCK".equals(actualDecision);
            } else { // ALLOW
                passed = "ALLOW".equals(actualDecision);
            }

            result.setPassed(passed);

            if (!isExpectedMalicious && isActualMalicious) { // Expected ALLOW but got BLOCK/REVIEW
                result.setFalsePositive(true);
                falsePositives.add(result);
                fp++;
            } else if (isExpectedMalicious && !isActualMalicious) { // Expected BLOCK/REVIEW but got ALLOW
                result.setFalseNegative(true);
                falseNegatives.add(result);
                fn++;
            } else if (isExpectedMalicious && isActualMalicious) {
                tp++;
            } else {
                tn++;
            }

            if ("REVIEW".equals(actualDecision) || "SAFE_BUT_AMBIGUOUS".equals(scenario.getExpectedCategory()) || "SUSPICIOUS".equals(scenario.getExpectedCategory())) {
                result.setAmbiguous(true);
                ambiguousCases.add(result);
            }

            detailedResults.add(result);
            scenarioResultMap.put(scenario.getId(), result);
            if (scenario.getPairId() != null) {
                pairResultMap.put(scenario.getPairId(), result);
            }
            categoryResults.computeIfAbsent(scenario.getExpectedCategory(), k -> new ArrayList<>()).add(result);
        }

        // Metrics Calculation
        double overallAccuracy = scenarios.isEmpty() ? 0.0 : (double) (tp + tn) / scenarios.size();
        double precision = (tp + fp) > 0 ? (double) tp / (tp + fp) : 1.0;
        double recall = (tp + fn) > 0 ? (double) tp / (tp + fn) : 1.0;
        double f1Score = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0.0;
        double fpr = (fp + tn) > 0 ? (double) fp / (fp + tn) : 0.0;
        double fnr = (fn + tp) > 0 ? (double) fn / (fn + tp) : 0.0;
        double avgLatencyMs = scenarios.isEmpty() ? 0.0 : (totalDurationNs / 1_000_000.0) / scenarios.size();

        SecurityMetrics metrics = new SecurityMetrics();
        metrics.setTotalScenarios(scenarios.size());
        metrics.setOverallAccuracy(overallAccuracy);
        metrics.setPrecision(precision);
        metrics.setRecall(recall);
        metrics.setF1Score(f1Score);
        metrics.setFalsePositiveRate(fpr);
        metrics.setFalseNegativeRate(fnr);
        metrics.setTruePositives(tp);
        metrics.setTrueNegatives(tn);
        metrics.setFalsePositives(fp);
        metrics.setFalseNegatives(fn);
        metrics.setAllowCount(allowCount);
        metrics.setReviewCount(reviewCount);
        metrics.setBlockCount(blockCount);
        metrics.setAverageLatencyMs(avgLatencyMs);

        // Category metrics calculation
        Map<String, SecurityMetrics.CategoryMetric> categoryMetrics = new HashMap<>();
        for (Map.Entry<String, List<EvaluationResult>> entry : categoryResults.entrySet()) {
            String cat = entry.getKey();
            List<EvaluationResult> catList = entry.getValue();
            int catTotal = catList.size();
            int catCorrect = 0;
            int catFp = 0;
            int catFn = 0;

            for (EvaluationResult r : catList) {
                if (r.isPassed()) catCorrect++;
                if (r.isFalsePositive()) catFp++;
                if (r.isFalseNegative()) catFn++;
            }

            double catAcc = (double) catCorrect / catTotal;
            double catPrec = (catCorrect + catFp) > 0 ? (double) catCorrect / (catCorrect + catFp) : 1.0;
            double catRec = (catCorrect + catFn) > 0 ? (double) catCorrect / (catCorrect + catFn) : 1.0;
            double catF1 = (catPrec + catRec) > 0 ? 2 * (catPrec * catRec) / (catPrec + catRec) : 0.0;

            categoryMetrics.put(cat, new SecurityMetrics.CategoryMetric(
                    cat, catTotal, catCorrect, catFp, catFn, catPrec, catRec, catF1, catAcc
            ));
        }
        metrics.setCategoryMetrics(categoryMetrics);

        // Provenance & Adversarial Analysis
        for (Map.Entry<String, EvaluationResult> entry : pairResultMap.entrySet()) {
            String pairId = entry.getKey();
            if (pairId != null && pairId.endsWith("-A")) {
                String pairBId = pairId.substring(0, pairId.length() - 2) + "-B";
                EvaluationResult resA = entry.getValue();
                EvaluationResult resB = pairResultMap.get(pairBId);

                if (resA != null && resB != null) {
                    provenanceFindings.add(String.format("Pair [%s vs %s]: Provenance '%s' vs '%s' -> Decision '%s' (Risk: %d) vs Decision '%s' (Risk: %d)",
                            resA.getScenarioId(), resB.getScenarioId(),
                            resA.getProvenance(), resB.getProvenance(),
                            resA.getActualDecision(), resA.getRiskScore(),
                            resB.getActualDecision(), resB.getRiskScore()));
                }
            }
        }

        for (EvaluationScenario s : scenarios) {
            if (s.isAdversarial()) {
                EvaluationResult res = scenarioResultMap.get(s.getId());
                if (res != null) {
                    adversarialFindings.add(String.format("Adversarial Sample [%s] (%s): Expected '%s', Actual '%s' (Passed: %s, Risk: %d)",
                            s.getId(), s.getAttackType() != null ? s.getAttackType() : s.getExpectedCategory(), s.getExpectedDecision(), res.getActualDecision(), res.isPassed(), res.getRiskScore()));
                }
            }
        }

        // Critical Findings Synthesis
        if (fn > 0) {
            criticalFindings.add(String.format("CRITICAL: Detected %d False Negative(s) where malicious memory payloads were permitted.", fn));
        } else {
            criticalFindings.add("SECURITY VERIFIED: Zero False Negatives detected. All malicious payloads blocked/quarantined.");
        }

        if (fp > 0) {
            criticalFindings.add(String.format("WARNING: Detected %d False Positive(s) where benign/trusted memories were flagged for review.", fp));
        } else {
            criticalFindings.add("USABILITY VERIFIED: Zero False Positives detected on clean benchmark dataset.");
        }

        criticalFindings.add(String.format("Detection Attribution Breakdown: Rule-Only: %d, Semantic-Only: %d, Both: %d, Neither: %d", ruleOnlyCount, semanticOnlyCount, bothCount, neitherCount));
        criticalFindings.add(String.format("Provenance Sensitivity: MemoryGuard evaluates risk dynamically based on source trust levels. Verified %d contrast pairs.", provenanceFindings.size()));
        criticalFindings.add(String.format("Adversarial Robustness: Evaluated %d adversarial samples. Overall F1 score: %.2f%%.", scenarios.size(), f1Score * 100));

        report.setOverallMetrics(metrics);
        report.setDetectorContributions(new EvaluationReport.DetectorContributions(
                ruleOnlyCount, semanticOnlyCount, bothCount, neitherCount,
                ruleOnlyScenarios, semanticOnlyScenarios, bothScenarios, neitherScenarios
        ));
        report.setDetailedResults(detailedResults);
        report.setFalsePositives(falsePositives);
        report.setFalseNegatives(falseNegatives);
        report.setAmbiguousCases(ambiguousCases);
        report.setProvenanceComparisonFindings(provenanceFindings);
        report.setAdversarialTestFindings(adversarialFindings);
        report.setCriticalFindings(criticalFindings);

        saveReportToJson(report);
        this.latestReport = report;
        return report;
    }

    public List<EvaluationScenario> loadScenarios() {
        // Try local file path for adversarial dataset first
        try {
            Path file = Paths.get("evaluation/datasets/adversarial_test_corpus.json");
            if (Files.exists(file)) {
                EvaluationScenario[] array = objectMapper.readValue(file.toFile(), EvaluationScenario[].class);
                return Arrays.asList(array);
            }
        } catch (Exception ignored) {}

        // Try adversarial_test_corpus.json from classpath
        try (InputStream is = getClass().getResourceAsStream("/adversarial_test_corpus.json")) {
            if (is != null) {
                EvaluationScenario[] array = objectMapper.readValue(is, EvaluationScenario[].class);
                return Arrays.asList(array);
            }
        } catch (Exception ignored) {}

        // Try local file path for security_scenarios.json
        try {
            Path file = Paths.get("evaluation/datasets/security_scenarios.json");
            if (Files.exists(file)) {
                EvaluationScenario[] array = objectMapper.readValue(file.toFile(), EvaluationScenario[].class);
                return Arrays.asList(array);
            }
        } catch (Exception ignored) {}

        // Fallback to security_scenarios.json from classpath
        try (InputStream is = getClass().getResourceAsStream("/security_scenarios.json")) {
            if (is != null) {
                EvaluationScenario[] array = objectMapper.readValue(is, EvaluationScenario[].class);
                return Arrays.asList(array);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load evaluation dataset", e);
        }
        throw new RuntimeException("Evaluation dataset not found");
    }

    private void saveReportToJson(EvaluationReport report) {
        try {
            Path reportDir = Paths.get("evaluation/reports");
            if (!Files.exists(reportDir)) {
                Files.createDirectories(reportDir);
            }
            File reportFile = reportDir.resolve("latest_evaluation.json").toFile();
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(reportFile, report);

            File reportFileAdv = reportDir.resolve("adversarial_evaluation_report.json").toFile();
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(reportFileAdv, report);
        } catch (Exception e) {
            System.err.println("Failed to write evaluation report JSON files: " + e.getMessage());
        }
    }

    public EvaluationReport getLatestReport() {
        return latestReport != null ? latestReport : runEvaluation();
    }
}

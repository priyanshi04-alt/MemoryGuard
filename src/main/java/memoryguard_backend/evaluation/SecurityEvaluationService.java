package memoryguard_backend.evaluation;

import memoryguard_backend.entity.Memory;
import memoryguard_backend.entity.ProvenanceType;
import memoryguard_backend.security.*;
import memoryguard_backend.security.content.ContentAnalysisResult;
import memoryguard_backend.security.content.ContentSecuritySignal;
import memoryguard_backend.security.content.MemoryContentAnalyzer;
import memoryguard_backend.security.context.ContextAnalysisResult;
import memoryguard_backend.security.context.ContextAnalyzer;
import memoryguard_backend.security.risk.MemoryRiskAggregator;
import memoryguard_backend.security.signals.SecuritySignalExtractor;
import memoryguard_backend.service.MemoryService;

import tools.jackson.databind.ObjectMapper;
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
    private final DatasetValidator datasetValidator;
    private EvaluationReport latestReport;

    @Autowired
    public SecurityEvaluationService(MemoryService memoryService) {
        this.memoryService = memoryService;
        this.objectMapper = new ObjectMapper();
        this.datasetValidator = new DatasetValidator();
    }

    public synchronized EvaluationReport runEvaluation() {
        return runEvaluation(EvaluationMode.RULES_PLUS_AI);
    }

    public synchronized EvaluationReport runEvaluation(EvaluationMode mode) {
        List<EvaluationScenario> scenarios = loadScenarios();
        if (mode == EvaluationMode.COMPARATIVE) {
            return runComparativeEvaluation(scenarios);
        }
        return runEvaluationOnScenarios(scenarios, mode);
    }

    public EvaluationReport runEvaluationOnScenarios(List<EvaluationScenario> scenarios) {
        return runEvaluationOnScenarios(scenarios, EvaluationMode.RULES_PLUS_AI);
    }

    public EvaluationReport runEvaluationOnScenarios(List<EvaluationScenario> scenarios, EvaluationMode mode) {
        if (scenarios == null || scenarios.isEmpty()) {
            scenarios = loadScenarios();
        }

        // Validate dataset
        datasetValidator.validate(scenarios);

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

        ConfusionMatrix confusionMatrix = new ConfusionMatrix();

        int allowCount = 0, reviewCount = 0, blockCount = 0;
        int ruleOnlyCount = 0, semanticOnlyCount = 0, bothCount = 0, neitherCount = 0;
        List<String> ruleOnlyScenarios = new ArrayList<>();
        List<String> semanticOnlyScenarios = new ArrayList<>();
        List<String> bothScenarios = new ArrayList<>();
        List<String> neitherScenarios = new ArrayList<>();

        long totalDurationNs = 0;

        // Analyzers for isolated evaluation execution
        MemoryContentAnalyzer contentAnalyzer = new MemoryContentAnalyzer();
        SecuritySignalExtractor signalExtractor = new SecuritySignalExtractor();
        ProvenanceAnalyzer provenanceAnalyzer = new ProvenanceAnalyzer();
        ContextAnalyzer contextAnalyzer = new ContextAnalyzer();
        BaselineSemanticAnalyzer semanticAnalyzer = new BaselineSemanticAnalyzer();
        RiskAggregator riskAggregator = new RiskAggregator();
        PolicyEngine policyEngine = new PolicyEngine();

        for (EvaluationScenario scenario : scenarios) {
            long startTime = System.nanoTime();

            // Run isolated security evaluation (without polluting production storage)
            String text = scenario.getMemoryContent();
            ProvenanceType prov = ProvenanceType.fromString(scenario.getProvenance());

            Memory mem = new Memory();
            mem.setContent(text);
            mem.setProvenance(prov);

            List<SecurityAnalysisResult> resultsList = new ArrayList<>();

            // 1. Provenance & Context Analysis
            ProvenanceAnalysisResult provRes = provenanceAnalyzer.analyze(mem);
            ContextAnalysisResult ctxRes = contextAnalyzer.analyze(mem);
            resultsList.add(provRes);
            resultsList.add(new SecurityAnalysisResult(
                    ctxRes.getRiskLevel(),
                    ctxRes.getRiskScore(),
                    ctxRes.getCategory(),
                    ctxRes.getReason(),
                    0.90,
                    "CONTEXT_ANALYZER"
            ));

            // 2. Content Rule Analysis
            ContentAnalysisResult ruleContentRes = contentAnalyzer.analyze(text);
            boolean ruleDetected = false;

            if (ruleContentRes != null && !ruleContentRes.getSignals().isEmpty()) {
                ruleDetected = true;
                ContentSecuritySignal primarySignal = ruleContentRes.getSignals().get(0);
                int ruleScore = "HIGH".equalsIgnoreCase(primarySignal.getSeverity()) || "CRITICAL".equalsIgnoreCase(primarySignal.getSeverity()) ? 85 : 50;
                resultsList.add(new SecurityAnalysisResult(
                        ruleScore >= 80 ? "HIGH" : "MEDIUM",
                        ruleScore,
                        primarySignal.getType() != null ? primarySignal.getType() : "RULE_SIGNAL",
                        primarySignal.getDescription() != null ? primarySignal.getDescription() : "Rule signal detected",
                        0.90,
                        "RULE_ANALYZER"
                ));
            }

            // 3. AI Semantic Analysis (Mode dependent)
            SemanticAnalysisResult semRes = null;
            boolean semanticDetected = false;

            if (mode != EvaluationMode.RULES_ONLY) {
                semRes = semanticAnalyzer.analyze(text);
                if (semRes != null) {
                    resultsList.add(semRes);
                    semanticDetected = semRes.getRiskScore() >= 50 && !"BENIGN_SECURITY_CONTENT".equals(semRes.getCategory());
                }
            }

            // 4. Risk Aggregation & PolicyEngine Decision Authority
            AggregatedRiskAssessment assessment = riskAggregator.aggregateAssessment(resultsList);
            PolicyDecisionResult decisionResult = policyEngine.evaluate(assessment);

            long endTime = System.nanoTime();
            double latencyMs = (endTime - startTime) / 1_000_000.0;
            totalDurationNs += (endTime - startTime);

            String actualDecision = decisionResult.getDecision().name(); // ALLOW, REVIEW, BLOCK
            String status = decisionResult.getPersistenceStatus(); // PERMITTED, QUARANTINED, DENIED

            if ("ALLOW".equals(actualDecision)) allowCount++;
            else if ("REVIEW".equals(actualDecision)) reviewCount++;
            else if ("BLOCK".equals(actualDecision)) blockCount++;

            int riskScore = decisionResult.getRiskScore();

            // Detector Attribution logic
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

            // Record into Confusion Matrix
            confusionMatrix.record(scenario.getExpectedDecision(), actualDecision);

            EvaluationResult result = new EvaluationResult();
            result.setScenarioId(scenario.getId());
            result.setAttackId(scenario.getId());
            result.setCategory(scenario.getExpectedCategory());
            result.setAttackCategory(scenario.getExpectedCategory());
            result.setProvenance(scenario.getProvenance());
            result.setAttackType(scenario.getAttackType());
            result.setMemoryContent(scenario.getMemoryContent());
            result.setExpectedDecision(scenario.getExpectedDecision());
            result.setExpectedRiskLevel(scenario.getExpectedRiskLevel() != null ? scenario.getExpectedRiskLevel() : "LOW");
            result.setExpectedSecurityReason(scenario.getExplanation());
            result.setActualDecision(actualDecision);
            result.setActualStatus("ALLOW".equals(actualDecision) ? "SAFE" : ("BLOCK".equals(actualDecision) ? "DENIED" : "QUARANTINED"));
            result.setActualFinalState(status);
            result.setRiskScore(riskScore);
            result.setRiskLevel(decisionResult.getRiskLevel());
            result.setRuleDetected(ruleDetected);
            result.setSemanticDetected(semanticDetected);
            result.setDetectionAttribution(attribution);
            result.setDecisionReason(decisionResult.getExplanation());
            result.setPolicyReason(decisionResult.getPolicyRule());
            result.setExplanation(scenario.getExplanation());
            result.setLatencyMs(latencyMs);

            List<String> analyzerContribs = new ArrayList<>();
            if (ruleDetected) analyzerContribs.add("RULE_ANALYZER");
            if (semanticDetected) analyzerContribs.add("SEMANTIC_ANALYZER");
            analyzerContribs.add("PROVENANCE_ANALYZER");
            analyzerContribs.add("CONTEXT_ANALYZER");
            result.setAnalyzerContributions(analyzerContribs);

            List<String> contribFactors = new ArrayList<>(decisionResult.getContributingFactors());
            contribFactors.add("MODE_" + mode.name());
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

            if (!isExpectedMalicious && isActualMalicious) {
                result.setFalsePositive(true);
                falsePositives.add(result);
            } else if (isExpectedMalicious && !isActualMalicious) {
                result.setFalseNegative(true);
                falseNegatives.add(result);
            }

            if ("REVIEW".equals(actualDecision) || "AMBIGUOUS".equals(datasetValidator.normalizeCategory(scenario.getExpectedCategory()))) {
                result.setAmbiguous(true);
                ambiguousCases.add(result);
            }

            if ("RETRIEVED".equalsIgnoreCase(scenario.getProvenance()) || "UNTRUSTED".equalsIgnoreCase(scenario.getProvenance()) || "EXTERNAL_TOOL".equalsIgnoreCase(scenario.getProvenance())) {
                provenanceFindings.add(String.format("Provenance contrast [%s]: High risk origin source '%s' evaluated for scenario '%s'.", mode, scenario.getProvenance(), scenario.getId()));
            }
            if (scenario.isAdversarial()) {
                adversarialFindings.add(String.format("Adversarial payload [%s]: Category '%s' evaluated with decision '%s'.", mode, scenario.getExpectedCategory(), actualDecision));
            }

            detailedResults.add(result);
            scenarioResultMap.put(scenario.getId(), result);
            if (scenario.getPairId() != null) {
                pairResultMap.put(scenario.getPairId(), result);
            }
            categoryResults.computeIfAbsent(scenario.getExpectedCategory(), k -> new ArrayList<>()).add(result);
        }

        // Calculate Security Metrics
        SecurityMetrics metrics = new SecurityMetrics();
        metrics.setTotalScenarios(scenarios.size());
        metrics.setOverallAccuracy(confusionMatrix.getAccuracy());
        metrics.setPrecision(confusionMatrix.getPrecision());
        metrics.setRecall(confusionMatrix.getRecall());
        metrics.setF1Score(confusionMatrix.getF1Score());
        metrics.setFalsePositiveRate(confusionMatrix.getFalsePositiveRate());
        metrics.setFalseNegativeRate(confusionMatrix.getFalseNegativeRate());
        metrics.setTruePositives(confusionMatrix.getTruePositives());
        metrics.setTrueNegatives(confusionMatrix.getTrueNegatives());
        metrics.setFalsePositives(confusionMatrix.getFalsePositives());
        metrics.setFalseNegatives(confusionMatrix.getFalseNegatives());
        metrics.setAllowCount(allowCount);
        metrics.setReviewCount(reviewCount);
        metrics.setBlockCount(blockCount);
        metrics.setAverageLatencyMs(scenarios.isEmpty() ? 0.0 : (totalDurationNs / 1_000_000.0) / scenarios.size());

        // Category Metrics
        Map<String, SecurityMetrics.CategoryMetric> categoryMetrics = new HashMap<>();
        for (Map.Entry<String, List<EvaluationResult>> entry : categoryResults.entrySet()) {
            String cat = entry.getKey();
            List<EvaluationResult> catList = entry.getValue();
            int catTotal = catList.size();
            int catCorrect = 0, catFp = 0, catFn = 0;

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

        // Findings Synthesis
        if (confusionMatrix.getFalseNegatives() > 0) {
            criticalFindings.add(String.format("CRITICAL [%s]: Detected %d False Negative(s) where malicious memory payloads were permitted.", mode, confusionMatrix.getFalseNegatives()));
        } else {
            criticalFindings.add(String.format("SECURITY VERIFIED [%s]: Zero False Negatives detected. All malicious payloads blocked/quarantined.", mode));
        }

        if (confusionMatrix.getFalsePositives() > 0) {
            criticalFindings.add(String.format("WARNING [%s]: Detected %d False Positive(s) where benign/trusted memories were flagged for review.", mode, confusionMatrix.getFalsePositives()));
        } else {
            criticalFindings.add(String.format("USABILITY VERIFIED [%s]: Zero False Positives detected.", mode));
        }

        criticalFindings.add(String.format("Evaluation Mode: %s. Overall F1 Score: %.2f%%, Accuracy: %.2f%%", mode, metrics.getF1Score() * 100, metrics.getOverallAccuracy() * 100));

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


    /**
     * Conducts a side-by-side comparative evaluation of RULES_ONLY vs RULES_PLUS_AI.
     */
    public EvaluationReport runComparativeEvaluation(List<EvaluationScenario> scenarios) {
        EvaluationReport reportRulesOnly = runEvaluationOnScenarios(scenarios, EvaluationMode.RULES_ONLY);
        EvaluationReport reportRulesPlusAi = runEvaluationOnScenarios(scenarios, EvaluationMode.RULES_PLUS_AI);

        EvaluationReport comparativeReport = new EvaluationReport();
        comparativeReport.setDatasetSize(scenarios.size());
        comparativeReport.setTotalCases(scenarios.size());
        comparativeReport.setOverallMetrics(reportRulesPlusAi.getOverallMetrics());
        comparativeReport.setDetailedResults(reportRulesPlusAi.getDetailedResults());
        comparativeReport.setFalsePositives(reportRulesPlusAi.getFalsePositives());
        comparativeReport.setFalseNegatives(reportRulesPlusAi.getFalseNegatives());
        comparativeReport.setAmbiguousCases(reportRulesPlusAi.getAmbiguousCases());

        List<String> findings = new ArrayList<>();
        SecurityMetrics mRules = reportRulesOnly.getOverallMetrics();
        SecurityMetrics mAi = reportRulesPlusAi.getOverallMetrics();

        findings.add("=== COMPARATIVE BENCHMARK SUMMARY: RULES_ONLY VS RULES_PLUS_AI ===");
        findings.add(String.format("RULES_ONLY   -> Accuracy: %.4f, Precision: %.4f, Recall: %.4f, F1: %.4f, FPR: %.4f, FNR: %.4f",
                mRules.getOverallAccuracy(), mRules.getPrecision(), mRules.getRecall(), mRules.getF1Score(), mRules.getFalsePositiveRate(), mRules.getFalseNegativeRate()));
        findings.add(String.format("RULES_PLUS_AI -> Accuracy: %.4f, Precision: %.4f, Recall: %.4f, F1: %.4f, FPR: %.4f, FNR: %.4f",
                mAi.getOverallAccuracy(), mAi.getPrecision(), mAi.getRecall(), mAi.getF1Score(), mAi.getFalsePositiveRate(), mAi.getFalseNegativeRate()));

        double f1Diff = mAi.getF1Score() - mRules.getF1Score();
        if (f1Diff > 0) {
            findings.add(String.format("SEMANTIC ADVANTAGE: RULES_PLUS_AI improved F1 Score by +%.2f%% over RULES_ONLY.", f1Diff * 100));
        } else if (f1Diff < 0) {
            findings.add(String.format("RULES ADVANTAGE: RULES_ONLY outperformed RULES_PLUS_AI by +%.2f%% F1 Score.", Math.abs(f1Diff) * 100));
        } else {
            findings.add("PARITY: Both RULES_ONLY and RULES_PLUS_AI achieved identical overall F1 Score performance.");
        }

        comparativeReport.setCriticalFindings(findings);
        this.latestReport = comparativeReport;
        return comparativeReport;
    }

    public List<EvaluationScenario> loadScenarios() {
        // Try benchmark_dataset.json first from resources or local file
        try (InputStream is = getClass().getResourceAsStream("/benchmark_dataset.json")) {
            if (is != null) {
                EvaluationScenario[] array = objectMapper.readValue(is, EvaluationScenario[].class);
                return Arrays.asList(array);
            }
        } catch (Exception ignored) {}

        try {
            Path file = Paths.get("evaluation/datasets/benchmark_dataset.json");
            if (Files.exists(file)) {
                EvaluationScenario[] array = objectMapper.readValue(file.toFile(), EvaluationScenario[].class);
                return Arrays.asList(array);
            }
        } catch (Exception ignored) {}

        // Fallback to adversarial_test_corpus.json
        try (InputStream is = getClass().getResourceAsStream("/adversarial_test_corpus.json")) {
            if (is != null) {
                EvaluationScenario[] array = objectMapper.readValue(is, EvaluationScenario[].class);
                return Arrays.asList(array);
            }
        } catch (Exception ignored) {}

        try {
            Path file = Paths.get("evaluation/datasets/adversarial_test_corpus.json");
            if (Files.exists(file)) {
                EvaluationScenario[] array = objectMapper.readValue(file.toFile(), EvaluationScenario[].class);
                return Arrays.asList(array);
            }
        } catch (Exception ignored) {}

        // Fallback to security_scenarios.json
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
        } catch (Exception e) {
            System.err.println("Failed to write evaluation report JSON files: " + e.getMessage());
        }
    }

    public EvaluationReport getLatestReport() {
        return latestReport != null ? latestReport : runEvaluation();
    }
}

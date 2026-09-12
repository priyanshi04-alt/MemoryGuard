package memoryguard_backend.evaluation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EvaluationReport {

    private String evaluationTimestamp = Instant.now().toString();
    private int datasetSize;
    private int totalCases;
    private int correct;
    private int falsePositivesCount;
    private int falseNegativesCount;
    private int truePositives;
    private int trueNegatives;
    private double precision;
    private double recall;
    private double f1Score;

    private Map<String, SecurityMetrics.CategoryMetric> categoryResults = new HashMap<>();
    private DetectorContributions detectorContributions = new DetectorContributions();

    private SecurityMetrics overallMetrics;
    private List<EvaluationResult> detailedResults = new ArrayList<>();
    private List<EvaluationResult> falsePositives = new ArrayList<>();
    private List<EvaluationResult> falseNegatives = new ArrayList<>();
    private List<EvaluationResult> ambiguousCases = new ArrayList<>();
    private List<String> provenanceComparisonFindings = new ArrayList<>();
    private List<String> adversarialTestFindings = new ArrayList<>();
    private List<String> criticalFindings = new ArrayList<>();

    public static class DetectorContributions {
        private int ruleOnly;
        private int semanticOnly;
        private int both;
        private int neither;
        private List<String> ruleOnlyScenarios = new ArrayList<>();
        private List<String> semanticOnlyScenarios = new ArrayList<>();
        private List<String> bothScenarios = new ArrayList<>();
        private List<String> neitherScenarios = new ArrayList<>();

        public DetectorContributions() {}

        public DetectorContributions(int ruleOnly, int semanticOnly, int both, int neither,
                                     List<String> ruleOnlyScenarios, List<String> semanticOnlyScenarios,
                                     List<String> bothScenarios, List<String> neitherScenarios) {
            this.ruleOnly = ruleOnly;
            this.semanticOnly = semanticOnly;
            this.both = both;
            this.neither = neither;
            this.ruleOnlyScenarios = ruleOnlyScenarios != null ? ruleOnlyScenarios : new ArrayList<>();
            this.semanticOnlyScenarios = semanticOnlyScenarios != null ? semanticOnlyScenarios : new ArrayList<>();
            this.bothScenarios = bothScenarios != null ? bothScenarios : new ArrayList<>();
            this.neitherScenarios = neitherScenarios != null ? neitherScenarios : new ArrayList<>();
        }

        public int getRuleOnly() { return ruleOnly; }
        public void setRuleOnly(int ruleOnly) { this.ruleOnly = ruleOnly; }

        public int getSemanticOnly() { return semanticOnly; }
        public void setSemanticOnly(int semanticOnly) { this.semanticOnly = semanticOnly; }

        public int getBoth() { return both; }
        public void setBoth(int both) { this.both = both; }

        public int getNeither() { return neither; }
        public void setNeither(int neither) { this.neither = neither; }

        public List<String> getRuleOnlyScenarios() { return ruleOnlyScenarios; }
        public void setRuleOnlyScenarios(List<String> ruleOnlyScenarios) { this.ruleOnlyScenarios = ruleOnlyScenarios; }

        public List<String> getSemanticOnlyScenarios() { return semanticOnlyScenarios; }
        public void setSemanticOnlyScenarios(List<String> semanticOnlyScenarios) { this.semanticOnlyScenarios = semanticOnlyScenarios; }

        public List<String> getBothScenarios() { return bothScenarios; }
        public void setBothScenarios(List<String> bothScenarios) { this.bothScenarios = bothScenarios; }

        public List<String> getNeitherScenarios() { return neitherScenarios; }
        public void setNeitherScenarios(List<String> neitherScenarios) { this.neitherScenarios = neitherScenarios; }
    }

    public EvaluationReport() {}

    public String getEvaluationTimestamp() {
        return evaluationTimestamp;
    }

    public void setEvaluationTimestamp(String evaluationTimestamp) {
        this.evaluationTimestamp = evaluationTimestamp;
    }

    public int getDatasetSize() {
        return datasetSize;
    }

    public void setDatasetSize(int datasetSize) {
        this.datasetSize = datasetSize;
        if (this.totalCases == 0) this.totalCases = datasetSize;
    }

    public int getTotalCases() {
        return totalCases != 0 ? totalCases : datasetSize;
    }

    public void setTotalCases(int totalCases) {
        this.totalCases = totalCases;
        this.datasetSize = totalCases;
    }

    public int getCorrect() {
        return correct;
    }

    public void setCorrect(int correct) {
        this.correct = correct;
    }

    public int getFalsePositivesCount() {
        return falsePositivesCount;
    }

    public void setFalsePositivesCount(int falsePositivesCount) {
        this.falsePositivesCount = falsePositivesCount;
    }

    public int getFalseNegativesCount() {
        return falseNegativesCount;
    }

    public void setFalseNegativesCount(int falseNegativesCount) {
        this.falseNegativesCount = falseNegativesCount;
    }

    public int getTruePositives() {
        return truePositives;
    }

    public void setTruePositives(int truePositives) {
        this.truePositives = truePositives;
    }

    public int getTrueNegatives() {
        return trueNegatives;
    }

    public void setTrueNegatives(int trueNegatives) {
        this.trueNegatives = trueNegatives;
    }

    public double getPrecision() {
        return precision;
    }

    public void setPrecision(double precision) {
        this.precision = precision;
    }

    public double getRecall() {
        return recall;
    }

    public void setRecall(double recall) {
        this.recall = recall;
    }

    public double getF1Score() {
        return f1Score;
    }

    public void setF1Score(double f1Score) {
        this.f1Score = f1Score;
    }

    public Map<String, SecurityMetrics.CategoryMetric> getCategoryResults() {
        return categoryResults;
    }

    public void setCategoryResults(Map<String, SecurityMetrics.CategoryMetric> categoryResults) {
        this.categoryResults = categoryResults;
    }

    public DetectorContributions getDetectorContributions() {
        return detectorContributions;
    }

    public void setDetectorContributions(DetectorContributions detectorContributions) {
        this.detectorContributions = detectorContributions;
    }

    public SecurityMetrics getOverallMetrics() {
        return overallMetrics;
    }

    public void setOverallMetrics(SecurityMetrics overallMetrics) {
        this.overallMetrics = overallMetrics;
        if (overallMetrics != null) {
            this.totalCases = overallMetrics.getTotalScenarios();
            this.truePositives = overallMetrics.getTruePositives();
            this.trueNegatives = overallMetrics.getTrueNegatives();
            this.falsePositivesCount = overallMetrics.getFalsePositives();
            this.falseNegativesCount = overallMetrics.getFalseNegatives();
            this.correct = overallMetrics.getTruePositives() + overallMetrics.getTrueNegatives();
            this.precision = overallMetrics.getPrecision();
            this.recall = overallMetrics.getRecall();
            this.f1Score = overallMetrics.getF1Score();
            if (overallMetrics.getCategoryMetrics() != null && !overallMetrics.getCategoryMetrics().isEmpty()) {
                this.categoryResults = overallMetrics.getCategoryMetrics();
            }
        }
    }

    public List<EvaluationResult> getDetailedResults() {
        return detailedResults;
    }

    public void setDetailedResults(List<EvaluationResult> detailedResults) {
        this.detailedResults = detailedResults;
    }

    public List<EvaluationResult> getFalsePositives() {
        return falsePositives;
    }

    public void setFalsePositives(List<EvaluationResult> falsePositives) {
        this.falsePositives = falsePositives;
        this.falsePositivesCount = falsePositives != null ? falsePositives.size() : 0;
    }

    public List<EvaluationResult> getFalseNegatives() {
        return falseNegatives;
    }

    public void setFalseNegatives(List<EvaluationResult> falseNegatives) {
        this.falseNegatives = falseNegatives;
        this.falseNegativesCount = falseNegatives != null ? falseNegatives.size() : 0;
    }

    public List<EvaluationResult> getAmbiguousCases() {
        return ambiguousCases;
    }

    public void setAmbiguousCases(List<EvaluationResult> ambiguousCases) {
        this.ambiguousCases = ambiguousCases;
    }

    public List<String> getProvenanceComparisonFindings() {
        return provenanceComparisonFindings;
    }

    public void setProvenanceComparisonFindings(List<String> provenanceComparisonFindings) {
        this.provenanceComparisonFindings = provenanceComparisonFindings;
    }

    public List<String> getAdversarialTestFindings() {
        return adversarialTestFindings;
    }

    public void setAdversarialTestFindings(List<String> adversarialTestFindings) {
        this.adversarialTestFindings = adversarialTestFindings;
    }

    public List<String> getCriticalFindings() {
        return criticalFindings;
    }

    public void setCriticalFindings(List<String> criticalFindings) {
        this.criticalFindings = criticalFindings;
    }
}

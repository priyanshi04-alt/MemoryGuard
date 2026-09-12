package memoryguard_backend.evaluation;

import java.util.HashMap;
import java.util.Map;

public class SecurityMetrics {

    private int totalScenarios;
    private double overallAccuracy;
    private double precision;
    private double recall;
    private double f1Score;
    private double falsePositiveRate;
    private double falseNegativeRate;

    private int truePositives;  // Malicious correctly BLOCKED or REVIEWED
    private int trueNegatives;  // Benign correctly ALLOWED
    private int falsePositives; // Benign incorrectly BLOCKED or REVIEWED
    private int falseNegatives; // Malicious incorrectly ALLOWED

    private int allowCount;
    private int reviewCount;
    private int blockCount;

    private double averageLatencyMs;

    private Map<String, CategoryMetric> categoryMetrics = new HashMap<>();

    public static class CategoryMetric {
        private String category;
        private int total;
        private int correct;
        private int falsePositives;
        private int falseNegatives;
        private double precision;
        private double recall;
        private double f1Score;
        private double accuracy;

        public CategoryMetric() {}

        public CategoryMetric(String category, int total, int correct, int falsePositives, int falseNegatives,
                              double precision, double recall, double f1Score, double accuracy) {
            this.category = category;
            this.total = total;
            this.correct = correct;
            this.falsePositives = falsePositives;
            this.falseNegatives = falseNegatives;
            this.precision = precision;
            this.recall = recall;
            this.f1Score = f1Score;
            this.accuracy = accuracy;
        }

        public String getCategory() { return category; }
        public void setCategory(String category) { this.category = category; }
        public int getTotal() { return total; }
        public void setTotal(int total) { this.total = total; }
        public int getCorrect() { return correct; }
        public void setCorrect(int correct) { this.correct = correct; }
        public int getFalsePositives() { return falsePositives; }
        public void setFalsePositives(int falsePositives) { this.falsePositives = falsePositives; }
        public int getFalseNegatives() { return falseNegatives; }
        public void setFalseNegatives(int falseNegatives) { this.falseNegatives = falseNegatives; }
        public double getPrecision() { return precision; }
        public void setPrecision(double precision) { this.precision = precision; }
        public double getRecall() { return recall; }
        public void setRecall(double recall) { this.recall = recall; }
        public double getF1Score() { return f1Score; }
        public void setF1Score(double f1Score) { this.f1Score = f1Score; }
        public double getAccuracy() { return accuracy; }
        public void setAccuracy(double accuracy) { this.accuracy = accuracy; }
    }

    public SecurityMetrics() {}

    public int getTotalScenarios() { return totalScenarios; }
    public void setTotalScenarios(int totalScenarios) { this.totalScenarios = totalScenarios; }

    public double getOverallAccuracy() { return overallAccuracy; }
    public void setOverallAccuracy(double overallAccuracy) { this.overallAccuracy = overallAccuracy; }

    public double getPrecision() { return precision; }
    public void setPrecision(double precision) { this.precision = precision; }

    public double getRecall() { return recall; }
    public void setRecall(double recall) { this.recall = recall; }

    public double getF1Score() { return f1Score; }
    public void setF1Score(double f1Score) { this.f1Score = f1Score; }

    public double getFalsePositiveRate() { return falsePositiveRate; }
    public void setFalsePositiveRate(double falsePositiveRate) { this.falsePositiveRate = falsePositiveRate; }

    public double getFalseNegativeRate() { return falseNegativeRate; }
    public void setFalseNegativeRate(double falseNegativeRate) { this.falseNegativeRate = falseNegativeRate; }

    public int getTruePositives() { return truePositives; }
    public void setTruePositives(int truePositives) { this.truePositives = truePositives; }

    public int getTrueNegatives() { return trueNegatives; }
    public void setTrueNegatives(int trueNegatives) { this.trueNegatives = trueNegatives; }

    public int getFalsePositives() { return falsePositives; }
    public void setFalsePositives(int falsePositives) { this.falsePositives = falsePositives; }

    public int getFalseNegatives() { return falseNegatives; }
    public void setFalseNegatives(int falseNegatives) { this.falseNegatives = falseNegatives; }

    public int getAllowCount() { return allowCount; }
    public void setAllowCount(int allowCount) { this.allowCount = allowCount; }

    public int getReviewCount() { return reviewCount; }
    public void setReviewCount(int reviewCount) { this.reviewCount = reviewCount; }

    public int getBlockCount() { return blockCount; }
    public void setBlockCount(int blockCount) { this.blockCount = blockCount; }

    public double getAverageLatencyMs() { return averageLatencyMs; }
    public void setAverageLatencyMs(double averageLatencyMs) { this.averageLatencyMs = averageLatencyMs; }

    public Map<String, CategoryMetric> getCategoryMetrics() { return categoryMetrics; }
    public void setCategoryMetrics(Map<String, CategoryMetric> categoryMetrics) { this.categoryMetrics = categoryMetrics; }
}

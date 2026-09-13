package memoryguard_backend.evaluation;

import java.util.HashMap;
import java.util.Map;

public class ConfusionMatrix {

    private int truePositives;
    private int trueNegatives;
    private int falsePositives;
    private int falseNegatives;

    // 3-Way Matrix: expectedDecision -> predictedDecision -> count
    private Map<String, Map<String, Integer>> decisionMatrix = new HashMap<>();

    public ConfusionMatrix() {
        initializeMatrix();
    }

    private void initializeMatrix() {
        String[] decisions = {"ALLOW", "REVIEW", "BLOCK"};
        for (String exp : decisions) {
            Map<String, Integer> row = new HashMap<>();
            for (String pred : decisions) {
                row.put(pred, 0);
            }
            decisionMatrix.put(exp, row);
        }
    }

    public void record(String expectedDecision, String predictedDecision) {
        String exp = expectedDecision != null ? expectedDecision.toUpperCase().trim() : "ALLOW";
        String pred = predictedDecision != null ? predictedDecision.toUpperCase().trim() : "ALLOW";

        decisionMatrix.computeIfAbsent(exp, k -> new HashMap<>())
                .put(pred, decisionMatrix.getOrDefault(exp, Map.of()).getOrDefault(pred, 0) + 1);

        boolean isExpectedThreat = "BLOCK".equals(exp) || "REVIEW".equals(exp);
        boolean isPredictedThreat = "BLOCK".equals(pred) || "REVIEW".equals(pred);

        if (isExpectedThreat && isPredictedThreat) {
            truePositives++;
        } else if (!isExpectedThreat && !isPredictedThreat) {
            trueNegatives++;
        } else if (!isExpectedThreat && isPredictedThreat) {
            falsePositives++;
        } else if (isExpectedThreat && !isPredictedThreat) {
            falseNegatives++;
        }
    }

    public int getTruePositives() {
        return truePositives;
    }

    public int getTrueNegatives() {
        return trueNegatives;
    }

    public int getFalsePositives() {
        return falsePositives;
    }

    public int getFalseNegatives() {
        return falseNegatives;
    }

    public int getTotalObservations() {
        return truePositives + trueNegatives + falsePositives + falseNegatives;
    }

    public double getAccuracy() {
        int total = getTotalObservations();
        return total > 0 ? (double) (truePositives + trueNegatives) / total : 0.0;
    }

    public double getPrecision() {
        int predictedPositives = truePositives + falsePositives;
        return predictedPositives > 0 ? (double) truePositives / predictedPositives : 1.0;
    }

    public double getRecall() {
        int actualPositives = truePositives + falseNegatives;
        return actualPositives > 0 ? (double) truePositives / actualPositives : 1.0;
    }

    public double getF1Score() {
        if (getTotalObservations() == 0) {
            return 0.0;
        }
        double prec = getPrecision();
        double rec = getRecall();
        return (prec + rec) > 0 ? 2 * (prec * rec) / (prec + rec) : 0.0;
    }

    public double getFalsePositiveRate() {
        int actualNegatives = falsePositives + trueNegatives;
        return actualNegatives > 0 ? (double) falsePositives / actualNegatives : 0.0;
    }

    public double getFalseNegativeRate() {
        int actualPositives = falseNegatives + truePositives;
        return actualPositives > 0 ? (double) falseNegatives / actualPositives : 0.0;
    }

    public Map<String, Map<String, Integer>> getDecisionMatrix() {
        return decisionMatrix;
    }

    public int getMatrixCell(String expected, String predicted) {
        if (expected == null || predicted == null) return 0;
        Map<String, Integer> row = decisionMatrix.get(expected.toUpperCase().trim());
        return row != null ? row.getOrDefault(predicted.toUpperCase().trim(), 0) : 0;
    }
}

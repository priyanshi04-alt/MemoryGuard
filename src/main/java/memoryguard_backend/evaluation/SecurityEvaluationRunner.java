package memoryguard_backend.evaluation;

import memoryguard_backend.security.*;
import memoryguard_backend.security.context.ContextAnalyzer;
import memoryguard_backend.security.signals.SecuritySignalExtractor;
import memoryguard_backend.security.content.MemoryContentAnalyzer;
import memoryguard_backend.security.risk.MemoryRiskAggregator;
import memoryguard_backend.service.MemoryService;
import memoryguard_backend.service.SecurityLogService;

import java.util.List;

public class SecurityEvaluationRunner {

    public static void main(String[] args) {
        System.out.println("Starting MemoryGuard Security Evaluation Suite...");

        BaselineSemanticAnalyzer baselineSemanticAnalyzer = new BaselineSemanticAnalyzer();
        ProvenanceAnalyzer provenanceAnalyzer = new ProvenanceAnalyzer();
        ContextAnalyzer contextAnalyzer = new ContextAnalyzer();
        SecuritySignalExtractor securitySignalExtractor = new SecuritySignalExtractor();
        MemoryContentAnalyzer memoryContentAnalyzer = new MemoryContentAnalyzer();
        MemoryRiskAggregator memoryRiskAggregator = new MemoryRiskAggregator();
        PolicyEngine policyEngine = new PolicyEngine();
        RiskAggregator riskAggregator = new RiskAggregator();

        MemoryService memoryService = new MemoryService(
                null,
                List.of(baselineSemanticAnalyzer),
                provenanceAnalyzer,
                contextAnalyzer,
                securitySignalExtractor,
                memoryContentAnalyzer,
                memoryRiskAggregator,
                null,
                policyEngine,
                riskAggregator,
                null,
                null
        );

        SecurityEvaluationService service = new SecurityEvaluationService(memoryService);
        EvaluationReport report = service.runEvaluation();

        SecurityMetrics m = report.getOverallMetrics();

        System.out.println("\nMemoryGuard Security Evaluation");
        System.out.println("--------------------------------");
        System.out.printf("Total Cases: %d%n%n", m.getTotalScenarios());

        System.out.printf("Overall Accuracy: %.1f%%%n", m.getOverallAccuracy() * 100);
        System.out.printf("Precision: %.1f%%%n", m.getPrecision() * 100);
        System.out.printf("Recall: %.1f%%%n", m.getRecall() * 100);
        System.out.printf("F1 Score: %.1f%%%n%n", m.getF1Score() * 100);

        System.out.printf("False Positives: %d%n", m.getFalsePositives());
        System.out.printf("False Negatives: %d%n%n", m.getFalseNegatives());

        System.out.println("Category Performance:");
        for (SecurityMetrics.CategoryMetric cm : m.getCategoryMetrics().values()) {
            System.out.printf("%-24s %.1f%%%n", cm.getCategory(), cm.getAccuracy() * 100);
        }

        System.out.println("\nCritical Findings:");
        for (String finding : report.getCriticalFindings()) {
            System.out.println("- " + finding);
        }
        System.out.println("--------------------------------\n");
    }
}

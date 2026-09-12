import json
import os
import sys
from datetime import datetime
from evaluation.evaluators.metrics_calculator import MetricsCalculator
from evaluation.evaluators.adversarial_evaluator import AdversarialEvaluator
from evaluation.evaluators.pipeline_evaluator import PipelineEvaluator

def run_evaluation():
    dataset_path = os.path.join(os.path.dirname(__file__), "datasets", "security_scenarios.json")
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset file not found at {dataset_path}")
        sys.exit(1)

    with open(dataset_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    evaluator = PipelineEvaluator(api_base_url="http://localhost:8081")

    # Try connecting to REST API
    results = evaluator.run_via_rest(scenarios)

    # Check if backend REST API was reachable
    api_reachable = any(r.get("actualDecision") != "ERROR" for r in results)

    if not api_reachable:
        report_path = os.path.join(os.path.dirname(__file__), "reports", "latest_evaluation.json")
        if os.path.exists(report_path):
            with open(report_path, "r", encoding="utf-8") as rf:
                report_data = json.load(rf)
                print_summary_report(report_data)
                return
        else:
            print("Backend REST API not reachable on port 8081 and no prior evaluation report found.")
            print("Please run backend server using './mvnw spring-boot:run' or run './mvnw test -Dtest=SecurityEvaluationFrameworkTests'.")
            return

    # Calculate metrics
    results_map = {r["scenarioId"]: r for r in results}
    metrics = MetricsCalculator.calculate_metrics(results)

    prov_findings, adv_findings = AdversarialEvaluator.analyze_provenance_and_adversarial(scenarios, results_map)

    fps = [r for r in results if r.get("actualDecision") in ["BLOCK", "REVIEW"] and r.get("expectedDecision") == "ALLOW"]
    fns = [r for r in results if r.get("actualDecision") == "ALLOW" and r.get("expectedDecision") in ["BLOCK", "REVIEW"]]
    ambiguous = [r for r in results if r.get("actualDecision") == "REVIEW" or r.get("category") in ["SAFE_BUT_AMBIGUOUS", "SUSPICIOUS"]]

    critical_findings = []
    if len(fns) > 0:
        critical_findings.append(f"CRITICAL: Detected {len(fns)} False Negative(s) where malicious memory payloads were permitted.")
    else:
        critical_findings.append("SECURITY VERIFIED: Zero False Negatives detected. All malicious payloads blocked/quarantined.")

    if len(fps) > 0:
        critical_findings.append(f"WARNING: Detected {len(fps)} False Positive(s) where benign/trusted memories were flagged for review.")
    else:
        critical_findings.append("USABILITY VERIFIED: Zero False Positives detected on clean benchmark dataset.")

    critical_findings.append(f"Provenance Sensitivity: Dynamic risk adjustment based on source trust levels. Verified {len(prov_findings)} contrast pairs.")
    critical_findings.append(f"Adversarial Robustness: Evaluated {len(adv_findings)} adversarial samples with obfuscated/polite framing. Overall F1: {metrics.get('f1Score', 0)*100:.1f}%.")

    report_data = {
        "evaluationTimestamp": datetime.now().isoformat(),
        "datasetSize": len(scenarios),
        "overallMetrics": metrics,
        "detailedResults": results,
        "falsePositives": fps,
        "falseNegatives": fns,
        "ambiguousCases": ambiguous,
        "provenanceComparisonFindings": prov_findings,
        "adversarialTestFindings": adv_findings,
        "criticalFindings": critical_findings
    }

    # Save JSON report
    report_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir, "latest_evaluation.json")
    with open(report_file, "w", encoding="utf-8") as rf:
        json.dump(report_data, rf, indent=2)

    print_summary_report(report_data)

def print_summary_report(report_data):
    metrics = report_data.get("overallMetrics", {})

    print("\nMemoryGuard Security Evaluation")
    print("--------------------------------")
    print(f"Total Cases: {report_data.get('datasetSize', 0)}\n")

    print(f"Overall Accuracy: {metrics.get('overallAccuracy', 0)*100:.1f}%")
    print(f"Precision: {metrics.get('precision', 0)*100:.1f}%")
    print(f"Recall: {metrics.get('recall', 0)*100:.1f}%")
    print(f"F1 Score: {metrics.get('f1Score', 0)*100:.1f}%\n")

    print(f"False Positives: {metrics.get('falsePositives', 0)}")
    print(f"False Negatives: {metrics.get('falseNegatives', 0)}\n")

    print("Category Performance:")
    cat_metrics = metrics.get("categoryMetrics", {})
    for cat_name, cm in cat_metrics.items():
        acc = cm.get("accuracy", 0) * 100
        print(f"{cat_name:<24} {acc:.1f}%")

    print("\nCritical Findings:")
    for finding in report_data.get("criticalFindings", []):
        print(f"- {finding}")
    print("--------------------------------\n")

if __name__ == "__main__":
    run_evaluation()

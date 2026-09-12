import math

class MetricsCalculator:
    """
    Computes security evaluation metrics including Accuracy, Precision, Recall,
    F1 Score, False Positive Rate (FPR), False Negative Rate (FNR), and category-wise performance.
    """

    @staticmethod
    def calculate_metrics(results):
        total = len(results)
        if total == 0:
            return {}

        tp = 0 # Malicious correctly BLOCKED or REVIEWED
        tn = 0 # Benign correctly ALLOWED
        fp = 0 # Benign incorrectly BLOCKED or REVIEWED
        fn = 0 # Malicious incorrectly ALLOWED

        allow_count = 0
        review_count = 0
        block_count = 0

        category_stats = {}

        for r in results:
            actual_dec = r.get("actualDecision")
            expected_dec = r.get("expectedDecision")
            category = r.get("category", "UNKNOWN")

            if actual_dec == "ALLOW":
                allow_count += 1
            elif actual_dec == "REVIEW":
                review_count += 1
            elif actual_dec == "BLOCK":
                block_count += 1

            is_expected_malicious = expected_dec in ["BLOCK", "REVIEW"]
            is_actual_malicious = actual_dec in ["BLOCK", "REVIEW"]

            passed = r.get("passed", False)

            if not is_expected_malicious and is_actual_malicious:
                fp += 1
            elif is_expected_malicious and not is_actual_malicious:
                fn += 1
            elif is_expected_malicious and is_actual_malicious:
                tp += 1
            else:
                tn += 1

            if category not in category_stats:
                category_stats[category] = {"total": 0, "correct": 0, "fp": 0, "fn": 0}

            c_stat = category_stats[category]
            c_stat["total"] += 1
            if passed:
                c_stat["correct"] += 1
            if not is_expected_malicious and is_actual_malicious:
                c_stat["fp"] += 1
            if is_expected_malicious and not is_actual_malicious:
                c_stat["fn"] += 1

        accuracy = (tp + tn) / total
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1_score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        cat_metrics = {}
        for cat, stats in category_stats.items():
            c_tot = stats["total"]
            c_corr = stats["correct"]
            c_fp = stats["fp"]
            c_fn = stats["fn"]

            c_acc = c_corr / c_tot if c_tot > 0 else 0.0
            c_prec = (c_corr / (c_corr + c_fp)) if (c_corr + c_fp) > 0 else 1.0
            c_rec = (c_corr / (c_corr + c_fn)) if (c_corr + c_fn) > 0 else 1.0
            c_f1 = (2 * c_prec * c_rec) / (c_prec + c_rec) if (c_prec + c_rec) > 0 else 0.0

            cat_metrics[cat] = {
                "category": cat,
                "total": c_tot,
                "correct": c_corr,
                "falsePositives": c_fp,
                "falseNegatives": c_fn,
                "accuracy": round(c_acc, 4),
                "precision": round(c_prec, 4),
                "recall": round(c_rec, 4),
                "f1Score": round(c_f1, 4)
            }

        return {
            "totalScenarios": total,
            "overallAccuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1Score": round(f1_score, 4),
            "falsePositiveRate": round(fpr, 4),
            "falseNegativeRate": round(fnr, 4),
            "truePositives": tp,
            "trueNegatives": tn,
            "falsePositives": fp,
            "falseNegatives": fn,
            "allowCount": allow_count,
            "reviewCount": review_count,
            "blockCount": block_count,
            "categoryMetrics": cat_metrics
        }

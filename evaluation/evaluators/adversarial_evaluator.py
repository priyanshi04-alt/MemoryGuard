class AdversarialEvaluator:
    """
    Evaluates adversarial perturbation robustness and provenance contrast sensitivity.
    """

    @staticmethod
    def analyze_provenance_and_adversarial(scenarios, results_map):
        provenance_findings = []
        adversarial_findings = []

        for s in scenarios:
            sid = s.get("id")
            pair_id = s.get("pairId")
            is_adv = s.get("isAdversarial", False)

            if pair_id and pair_id.endswith("-A"):
                pair_b_id = pair_id.replace("-A", "-B")
                res_a = results_map.get(sid)
                res_b = results_map.get(pair_b_id)

                if res_a and res_b:
                    finding = (
                        f"Pair [{res_a.get('scenarioId')} vs {res_b.get('scenarioId')}]: "
                        f"Provenance '{res_a.get('provenance')}' vs '{res_b.get('provenance')}' -> "
                        f"Decision '{res_a.get('actualDecision')}' (Risk: {res_a.get('riskScore')}) vs "
                        f"Decision '{res_b.get('actualDecision')}' (Risk: {res_b.get('riskScore')})"
                    )
                    provenance_findings.append(finding)

            if is_adv:
                res = results_map.get(sid)
                if res:
                    finding = (
                        f"Adversarial Sample [{sid}] ({s.get('attackType')}): "
                        f"Expected '{s.get('expectedDecision')}', Actual '{res.get('actualDecision')}' "
                        f"(Passed: {res.get('passed')}, Risk Score: {res.get('riskScore')})"
                    )
                    adversarial_findings.append(finding)

        return provenance_findings, adversarial_findings

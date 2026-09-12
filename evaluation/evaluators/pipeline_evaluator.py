import json
import urllib.request
import time

class PipelineEvaluator:
    """
    Evaluator that submits scenarios to the live MemoryGuard security pipeline
    and captures complete security decision artifacts.
    """

    def __init__(self, api_base_url="http://localhost:8081"):
        self.api_base_url = api_base_url

    def run_via_rest(self, scenarios):
        results = []
        for s in scenarios:
            payload = {
                "content": s.get("memoryContent"),
                "provenance": s.get("provenance", "USER_INPUT")
            }
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.api_base_url}/api/memories",
                data=req_data,
                headers={"Content-Type": "application/json"}
            )

            start_time = time.time()
            try:
                with urllib.request.urlopen(req, timeout=0.5) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    latency_ms = (time.time() - start_time) * 1000.0

                    status = resp_data.get("status") # SAFE, QUARANTINED, DENIED
                    actual_decision = "ALLOW" if status == "SAFE" else ("BLOCK" if status == "DENIED" else "REVIEW")
                    risk_score = resp_data.get("riskScore", 0)

                    expected_decision = s.get("expectedDecision")
                    passed = self._check_passed(expected_decision, actual_decision)

                    results.append({
                        "scenarioId": s.get("id"),
                        "category": s.get("expectedCategory"),
                        "provenance": s.get("provenance"),
                        "attackType": s.get("attackType"),
                        "memoryContent": s.get("memoryContent"),
                        "expectedDecision": expected_decision,
                        "actualDecision": actual_decision,
                        "actualStatus": status,
                        "riskScore": risk_score,
                        "riskLevel": "CRITICAL" if risk_score >= 75 else ("HIGH" if risk_score >= 50 else ("MEDIUM" if risk_score >= 25 else "LOW")),
                        "decisionReason": resp_data.get("riskReason", ""),
                        "explanation": s.get("explanation"),
                        "latencyMs": round(latency_ms, 2),
                        "passed": passed
                    })
            except Exception as e:
                # Handle error or offline backend safely
                results.append({
                    "scenarioId": s.get("id"),
                    "category": s.get("expectedCategory"),
                    "provenance": s.get("provenance"),
                    "attackType": s.get("attackType"),
                    "memoryContent": s.get("memoryContent"),
                    "expectedDecision": s.get("expectedDecision"),
                    "actualDecision": "ERROR",
                    "actualStatus": "ERROR",
                    "riskScore": -1,
                    "riskLevel": "UNKNOWN",
                    "decisionReason": str(e),
                    "explanation": s.get("explanation"),
                    "latencyMs": 0.0,
                    "passed": False
                })
        return results

    def _check_passed(self, expected, actual):
        if expected == "BLOCK":
            return actual == "BLOCK"
        elif expected == "REVIEW":
            return actual in ["REVIEW", "BLOCK"]
        else: # ALLOW
            return actual == "ALLOW"

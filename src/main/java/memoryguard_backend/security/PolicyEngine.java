package memoryguard_backend.security;

import org.springframework.stereotype.Component;

@Component
public class PolicyEngine {

    public PolicyDecision decide(int riskScore) {

        if (riskScore >= 80) {
            return PolicyDecision.BLOCK;
        }

        if (riskScore >= 50) {
            return PolicyDecision.REVIEW;
        }

        return PolicyDecision.ALLOW;
    }
}
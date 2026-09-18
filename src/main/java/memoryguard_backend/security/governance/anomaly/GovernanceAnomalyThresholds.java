package memoryguard_backend.security.governance.anomaly;

import org.springframework.stereotype.Component;

/**
 * Centralized, explainable threshold parameters for Governance Anomaly Detection.
 */
@Component
public class GovernanceAnomalyThresholds {

    /** Observation time window in minutes for rapid activity detection */
    private int windowMinutes = 15;

    /** Maximum governance actions by a single operator within windowMinutes before RAPID_GOVERNANCE_ACTIVITY */
    private int maxGovernanceActionsPerWindow = 5;

    /** Maximum policy activations within windowMinutes before RAPID_POLICY_ACTIVATION */
    private int maxPolicyActivationsPerWindow = 2;

    /** Minimum rejection ratio (rejections / total proposals) before REPEATED_REJECTION_PATTERN */
    private double rejectionRatioThreshold = 0.50;

    /** Minimum approval ratio (approvals / total proposals) before REPEATED_APPROVAL_PATTERN */
    private double approvalRatioThreshold = 0.80;

    /** Minimum policy version switch count between identical thresholds/versions before POLICY_FLAPPING */
    private int flappingSwitchCountThreshold = 3;

    /** Minimum unauthorized or forbidden governance audit events within windowMinutes before UNAUTHORIZED_GOVERNANCE_ATTEMPTS */
    private int unauthorizedAttemptsThreshold = 2;

    public GovernanceAnomalyThresholds() {
    }

    public int getWindowMinutes() { return windowMinutes; }
    public void setWindowMinutes(int windowMinutes) { this.windowMinutes = windowMinutes; }

    public int getMaxGovernanceActionsPerWindow() { return maxGovernanceActionsPerWindow; }
    public void setMaxGovernanceActionsPerWindow(int maxGovernanceActionsPerWindow) { this.maxGovernanceActionsPerWindow = maxGovernanceActionsPerWindow; }

    public int getMaxPolicyActivationsPerWindow() { return maxPolicyActivationsPerWindow; }
    public void setMaxPolicyActivationsPerWindow(int maxPolicyActivationsPerWindow) { this.maxPolicyActivationsPerWindow = maxPolicyActivationsPerWindow; }

    public double getRejectionRatioThreshold() { return rejectionRatioThreshold; }
    public void setRejectionRatioThreshold(double rejectionRatioThreshold) { this.rejectionRatioThreshold = rejectionRatioThreshold; }

    public double getApprovalRatioThreshold() { return approvalRatioThreshold; }
    public void setApprovalRatioThreshold(double approvalRatioThreshold) { this.approvalRatioThreshold = approvalRatioThreshold; }

    public int getFlappingSwitchCountThreshold() { return flappingSwitchCountThreshold; }
    public void setFlappingSwitchCountThreshold(int flappingSwitchCountThreshold) { this.flappingSwitchCountThreshold = flappingSwitchCountThreshold; }

    public int getUnauthorizedAttemptsThreshold() { return unauthorizedAttemptsThreshold; }
    public void setUnauthorizedAttemptsThreshold(int unauthorizedAttemptsThreshold) { this.unauthorizedAttemptsThreshold = unauthorizedAttemptsThreshold; }
}

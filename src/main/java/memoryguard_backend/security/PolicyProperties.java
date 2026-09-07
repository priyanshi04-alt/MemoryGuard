package memoryguard_backend.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "memoryguard.policy")
public class PolicyProperties {

    private int blockThreshold = 80;
    private int reviewThreshold = 50;
    private double highConfidenceThreshold = 0.70;
    private boolean criticalThreatAutoBlock = true;
    private String failSafeDefaultDecision = "REVIEW";

    public int getBlockThreshold() {
        return blockThreshold;
    }

    public void setBlockThreshold(int blockThreshold) {
        this.blockThreshold = blockThreshold;
    }

    public int getReviewThreshold() {
        return reviewThreshold;
    }

    public void setReviewThreshold(int reviewThreshold) {
        this.reviewThreshold = reviewThreshold;
    }

    public double getHighConfidenceThreshold() {
        return highConfidenceThreshold;
    }

    public void setHighConfidenceThreshold(double highConfidenceThreshold) {
        this.highConfidenceThreshold = highConfidenceThreshold;
    }

    public boolean isCriticalThreatAutoBlock() {
        return criticalThreatAutoBlock;
    }

    public void setCriticalThreatAutoBlock(boolean criticalThreatAutoBlock) {
        this.criticalThreatAutoBlock = criticalThreatAutoBlock;
    }

    public String getFailSafeDefaultDecision() {
        return failSafeDefaultDecision;
    }

    public void setFailSafeDefaultDecision(String failSafeDefaultDecision) {
        this.failSafeDefaultDecision = failSafeDefaultDecision;
    }
}

package memoryguard_backend.dto;

import java.util.List;

public class PolicyAnalyticsResponse {

    private int totalPolicyVersions;
    private int activatedVersionsCount;
    private int supersededVersionsCount;
    private PolicyVersionResponse currentActiveVersion;
    private int currentReviewThreshold;
    private int currentBlockThreshold;
    private Integer previousReviewThreshold;
    private Integer previousBlockThreshold;
    private List<PolicyVersionResponse> policyChangesTimeline;

    public PolicyAnalyticsResponse() {
    }

    public PolicyAnalyticsResponse(
            int totalPolicyVersions,
            int activatedVersionsCount,
            int supersededVersionsCount,
            PolicyVersionResponse currentActiveVersion,
            int currentReviewThreshold,
            int currentBlockThreshold,
            Integer previousReviewThreshold,
            Integer previousBlockThreshold,
            List<PolicyVersionResponse> policyChangesTimeline) {
        this.totalPolicyVersions = totalPolicyVersions;
        this.activatedVersionsCount = activatedVersionsCount;
        this.supersededVersionsCount = supersededVersionsCount;
        this.currentActiveVersion = currentActiveVersion;
        this.currentReviewThreshold = currentReviewThreshold;
        this.currentBlockThreshold = currentBlockThreshold;
        this.previousReviewThreshold = previousReviewThreshold;
        this.previousBlockThreshold = previousBlockThreshold;
        this.policyChangesTimeline = policyChangesTimeline;
    }

    public int getTotalPolicyVersions() { return totalPolicyVersions; }
    public void setTotalPolicyVersions(int totalPolicyVersions) { this.totalPolicyVersions = totalPolicyVersions; }

    public int getActivatedVersionsCount() { return activatedVersionsCount; }
    public void setActivatedVersionsCount(int activatedVersionsCount) { this.activatedVersionsCount = activatedVersionsCount; }

    public int getSupersededVersionsCount() { return supersededVersionsCount; }
    public void setSupersededVersionsCount(int supersededVersionsCount) { this.supersededVersionsCount = supersededVersionsCount; }

    public PolicyVersionResponse getCurrentActiveVersion() { return currentActiveVersion; }
    public void setCurrentActiveVersion(PolicyVersionResponse currentActiveVersion) { this.currentActiveVersion = currentActiveVersion; }

    public int getCurrentReviewThreshold() { return currentReviewThreshold; }
    public void setCurrentReviewThreshold(int currentReviewThreshold) { this.currentReviewThreshold = currentReviewThreshold; }

    public int getCurrentBlockThreshold() { return currentBlockThreshold; }
    public void setCurrentBlockThreshold(int currentBlockThreshold) { this.currentBlockThreshold = currentBlockThreshold; }

    public Integer getPreviousReviewThreshold() { return previousReviewThreshold; }
    public void setPreviousReviewThreshold(Integer previousReviewThreshold) { this.previousReviewThreshold = previousReviewThreshold; }

    public Integer getPreviousBlockThreshold() { return previousBlockThreshold; }
    public void setPreviousBlockThreshold(Integer previousBlockThreshold) { this.previousBlockThreshold = previousBlockThreshold; }

    public List<PolicyVersionResponse> getPolicyChangesTimeline() { return policyChangesTimeline; }
    public void setPolicyChangesTimeline(List<PolicyVersionResponse> policyChangesTimeline) { this.policyChangesTimeline = policyChangesTimeline; }
}

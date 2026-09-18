package memoryguard_backend.dto;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class GovernanceAnomalySummaryResponse {

    private long totalFindings;
    private long openFindings;
    private long acknowledgedFindings;
    private long resolvedFindings;
    private Map<String, Long> bySeverity;
    private Map<String, Long> byAnomalyType;
    private List<GovernanceFindingResponse> recentFindings;
    private LocalDateTime lastScanTimestamp;

    public GovernanceAnomalySummaryResponse() {
    }

    public GovernanceAnomalySummaryResponse(
            long totalFindings,
            long openFindings,
            long acknowledgedFindings,
            long resolvedFindings,
            Map<String, Long> bySeverity,
            Map<String, Long> byAnomalyType,
            List<GovernanceFindingResponse> recentFindings,
            LocalDateTime lastScanTimestamp) {
        this.totalFindings = totalFindings;
        this.openFindings = openFindings;
        this.acknowledgedFindings = acknowledgedFindings;
        this.resolvedFindings = resolvedFindings;
        this.bySeverity = bySeverity;
        this.byAnomalyType = byAnomalyType;
        this.recentFindings = recentFindings;
        this.lastScanTimestamp = lastScanTimestamp;
    }

    public long getTotalFindings() { return totalFindings; }
    public void setTotalFindings(long totalFindings) { this.totalFindings = totalFindings; }

    public long getOpenFindings() { return openFindings; }
    public void setOpenFindings(long openFindings) { this.openFindings = openFindings; }

    public long getAcknowledgedFindings() { return acknowledgedFindings; }
    public void setAcknowledgedFindings(long acknowledgedFindings) { this.acknowledgedFindings = acknowledgedFindings; }

    public long getResolvedFindings() { return resolvedFindings; }
    public void setResolvedFindings(long resolvedFindings) { this.resolvedFindings = resolvedFindings; }

    public Map<String, Long> getBySeverity() { return bySeverity; }
    public void setBySeverity(Map<String, Long> bySeverity) { this.bySeverity = bySeverity; }

    public Map<String, Long> getByAnomalyType() { return byAnomalyType; }
    public void setByAnomalyType(Map<String, Long> byAnomalyType) { this.byAnomalyType = byAnomalyType; }

    public List<GovernanceFindingResponse> getRecentFindings() { return recentFindings; }
    public void setRecentFindings(List<GovernanceFindingResponse> recentFindings) { this.recentFindings = recentFindings; }

    public LocalDateTime getLastScanTimestamp() { return lastScanTimestamp; }
    public void setLastScanTimestamp(LocalDateTime lastScanTimestamp) { this.lastScanTimestamp = lastScanTimestamp; }
}

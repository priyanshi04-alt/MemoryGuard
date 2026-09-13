package memoryguard_backend.dto;

import java.util.ArrayList;
import java.util.List;

public class CalibrationResponse {

    private int minimumThreshold = 10;
    private long totalObservations;
    private boolean isSufficientData;
    private String status;
    private List<CalibrationRecommendation> recommendations = new ArrayList<>();

    public CalibrationResponse() {
    }

    public CalibrationResponse(int minimumThreshold, long totalObservations, boolean isSufficientData,
                               String status, List<CalibrationRecommendation> recommendations) {
        this.minimumThreshold = minimumThreshold;
        this.totalObservations = totalObservations;
        this.isSufficientData = isSufficientData;
        this.status = status;
        this.recommendations = recommendations != null ? recommendations : new ArrayList<>();
    }

    public int getMinimumThreshold() {
        return minimumThreshold;
    }

    public void setMinimumThreshold(int minimumThreshold) {
        this.minimumThreshold = minimumThreshold;
    }

    public long getTotalObservations() {
        return totalObservations;
    }

    public void setTotalObservations(long totalObservations) {
        this.totalObservations = totalObservations;
    }

    public boolean isSufficientData() {
        return isSufficientData;
    }

    public void setSufficientData(boolean sufficientData) {
        isSufficientData = sufficientData;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public List<CalibrationRecommendation> getRecommendations() {
        return recommendations;
    }

    public void setRecommendations(List<CalibrationRecommendation> recommendations) {
        this.recommendations = recommendations;
    }
}

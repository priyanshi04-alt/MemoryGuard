package memoryguard_backend.security.content;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Result model produced by MemoryContentAnalyzer containing extracted security signals.
 */
public class ContentAnalysisResult {

    private String memory;
    private List<ContentSecuritySignal> signals = new ArrayList<>();

    public ContentAnalysisResult() {
    }

    public ContentAnalysisResult(String memory, List<ContentSecuritySignal> signals) {
        this.memory = memory;
        this.signals = signals != null ? signals : new ArrayList<>();
    }

    public String getMemory() {
        return memory;
    }

    public void setMemory(String memory) {
        this.memory = memory;
    }

    public List<ContentSecuritySignal> getSignals() {
        return signals;
    }

    public void setSignals(List<ContentSecuritySignal> signals) {
        this.signals = signals != null ? signals : new ArrayList<>();
    }

    public void addSignal(ContentSecuritySignal signal) {
        if (signal != null) {
            this.signals.add(signal);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ContentAnalysisResult that = (ContentAnalysisResult) o;
        return Objects.equals(memory, that.memory) &&
               Objects.equals(signals, that.signals);
    }

    @Override
    public int hashCode() {
        return Objects.hash(memory, signals);
    }

    @Override
    public String toString() {
        return "ContentAnalysisResult{" +
                "memory='" + memory + '\'' +
                ", signalsCount=" + signals.size() +
                '}';
    }
}

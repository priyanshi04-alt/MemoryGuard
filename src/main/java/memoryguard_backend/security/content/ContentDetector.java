package memoryguard_backend.security.content;

import java.util.List;

/**
 * Interface for modular memory content security detectors.
 */
public interface ContentDetector {

    /**
     * Inspects content and returns a list of detected ContentSecuritySignal instances.
     *
     * @param content raw memory content string
     * @return list of detected security signals (empty if none detected)
     */
    List<ContentSecuritySignal> detect(String content);
}

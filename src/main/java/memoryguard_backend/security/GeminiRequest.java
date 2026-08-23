package memoryguard_backend.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;

public record GeminiRequest(
    List<Content> contents,
    GenerationConfig generationConfig
) {
    public record Content(List<Part> parts) {}

    public record Part(String text) {}

    public record GenerationConfig(
        String responseMimeType,
        ResponseSchema responseSchema
    ) {}

    public record ResponseSchema(
        String type,
        Map<String, Property> properties,
        List<String> required
    ) {}

    public record Property(
        String type,
        @JsonProperty("enum") List<String> enumeration
    ) {
        public Property(String type) {
            this(type, null);
        }
    }
}

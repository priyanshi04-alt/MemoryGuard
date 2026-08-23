package memoryguard_backend;

import tools.jackson.databind.ObjectMapper;
import memoryguard_backend.security.AIServiceException;
import memoryguard_backend.security.AiConfigProperties;
import memoryguard_backend.security.GeminiAIService;
import memoryguard_backend.security.SecurityAnalysisResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class GeminiAIServiceTests {

    private AiConfigProperties aiConfigProperties;
    private ObjectMapper objectMapper;
    private GeminiAIService geminiAIService;
    private MockRestServiceServer mockServer;

    @BeforeEach
    void setUp() {
        aiConfigProperties = new AiConfigProperties();
        aiConfigProperties.setEnabled(true);
        aiConfigProperties.setApiKey("mock-api-key");
        aiConfigProperties.setProvider("gemini");
        aiConfigProperties.setModel("gemini-2.5-flash");
        aiConfigProperties.setConnectTimeoutMs(1000);
        aiConfigProperties.setReadTimeoutMs(3000);
        aiConfigProperties.setMaxInputLength(2000);

        objectMapper = new ObjectMapper();

        RestClient.Builder builder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(builder).build();
        RestClient restClient = builder.build();

        geminiAIService = new GeminiAIService(aiConfigProperties, objectMapper, restClient);
    }

    @Test
    void validHighRiskSemanticResponse() {
        String mockResponse = createGeminiResponseJson("HIGH", 90, "PROMPT_INJECTION", 0.95, "Prompt override detected");
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        SecurityAnalysisResult result = geminiAIService.evaluate("Direct injection query");
        
        assertNotNull(result);
        assertEquals("HIGH", result.getRiskLevel());
        assertEquals(90, result.getRiskScore());
        assertEquals("PROMPT_INJECTION", result.getCategory());
        assertEquals(0.95, result.getConfidence());
        assertEquals("Prompt override detected", result.getReason());
        assertEquals("SEMANTIC", result.getAnalyzerType());
    }

    @Test
    void validMediumRiskSemanticResponse() {
        String mockResponse = createGeminiResponseJson("MEDIUM", 55, "CREDENTIAL_REFERENCE", 0.80, "Mentions password storage safety");
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        SecurityAnalysisResult result = geminiAIService.evaluate("How can I safely store my password?");
        
        assertNotNull(result);
        assertEquals("MEDIUM", result.getRiskLevel());
        assertEquals(55, result.getRiskScore());
        assertEquals("CREDENTIAL_REFERENCE", result.getCategory());
        assertEquals(0.80, result.getConfidence());
        assertEquals("SEMANTIC", result.getAnalyzerType());
    }

    @Test
    void validLowRiskSemanticResponse() {
        String mockResponse = createGeminiResponseJson("LOW", 10, "NONE", 0.99, "Normal preferences conversation");
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        SecurityAnalysisResult result = geminiAIService.evaluate("I prefer dark mode in my IDE.");
        
        assertNotNull(result);
        assertEquals("LOW", result.getRiskLevel());
        assertEquals(10, result.getRiskScore());
        assertEquals("NONE", result.getCategory());
        assertEquals(0.99, result.getConfidence());
    }

    @Test
    void invalidRiskScoreGreaterThan100() {
        String mockResponse = createGeminiResponseJson("HIGH", 101, "PROMPT_INJECTION", 0.95, "Score out of range");
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.INVALID_RESULT, exception.getFailureType());
        assertTrue(exception.getMessage().contains("riskScore"));
    }

    @Test
    void invalidRiskScoreLessThan0() {
        String mockResponse = createGeminiResponseJson("LOW", -5, "NONE", 0.95, "Negative score");
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.INVALID_RESULT, exception.getFailureType());
    }

    @Test
    void invalidConfidenceGreaterThan1() {
        String mockResponse = createGeminiResponseJson("LOW", 10, "NONE", 1.05, "Confidence too high");
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.INVALID_RESULT, exception.getFailureType());
    }

    @Test
    void invalidConfidenceLessThan0() {
        String mockResponse = createGeminiResponseJson("LOW", 10, "NONE", -0.05, "Negative confidence");
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.INVALID_RESULT, exception.getFailureType());
    }

    @Test
    void missingRequiredField() {
        // Response missing "riskScore"
        String mockResponse = "{\n" +
                "  \"candidates\": [\n" +
                "    {\n" +
                "      \"content\": {\n" +
                "        \"parts\": [\n" +
                "          {\n" +
                "            \"text\": \"{\\n  \\\"riskLevel\\\": \\\"LOW\\\",\\n  \\\"threatCategory\\\": \\\"NONE\\\",\\n  \\\"confidence\\\": 0.99,\\n  \\\"reason\\\": \\\"Reason\\\"\\n}\"\n" +
                "          }\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.INVALID_RESULT, exception.getFailureType());
        assertTrue(exception.getMessage().contains("riskScore"));
    }

    @Test
    void malformedJson() {
        String mockResponse = "{\n" +
                "  \"candidates\": [\n" +
                "    {\n" +
                "      \"content\": {\n" +
                "        \"parts\": [\n" +
                "          {\n" +
                "            \"text\": \"Hello World, this is not JSON\"\n" +
                "          }\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.MALFORMED_RESPONSE, exception.getFailureType());
    }

    @Test
    void httpError() {
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.HTTP_ERROR, exception.getFailureType());
        assertTrue(exception.getMessage().contains("500"));
    }

    @Test
    void timeoutThrowsAIServiceException() {
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(request -> {
                    throw new ResourceAccessException("Timeout", new SocketTimeoutException("Read timed out"));
                });

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.TIMEOUT, exception.getFailureType());
    }

    @Test
    void inputExceedingMaxLength() {
        // Construct 2001 chars string
        StringBuilder content = new StringBuilder();
        for (int i = 0; i < 2001; i++) {
            content.append("A");
        }

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate(content.toString())
        );
        assertEquals(AIServiceException.FailureType.INPUT_EXCEEDED, exception.getFailureType());
    }

    @Test
    void blankInput() {
        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("   ")
        );
        assertEquals(AIServiceException.FailureType.BLANK_INPUT, exception.getFailureType());
    }

    @Test
    void verifyApiKeyIsNeverExposed() {
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        
        // Assert that the exception message does not contain the key value
        assertFalse(exception.getMessage().contains("mock-api-key"));
        if (exception.getCause() != null) {
            assertFalse(exception.getCause().getMessage().contains("mock-api-key"));
        }
    }

    @Test
    void invalidRiskScoreTypeMismatchString() {
        String mockResponse = createGeminiResponseJsonText("\"85\"", "\"HIGH\"", "\"PROMPT_INJECTION\"", "0.95", "\"Type mismatch\"");
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.INVALID_RESULT, exception.getFailureType());
        assertTrue(exception.getMessage().contains("riskScore"));
    }

    @Test
    void invalidConfidenceTypeMismatchString() {
        String mockResponse = createGeminiResponseJsonText("85", "\"HIGH\"", "\"PROMPT_INJECTION\"", "\"0.95\"", "\"Type mismatch\"");
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.INVALID_RESULT, exception.getFailureType());
        assertTrue(exception.getMessage().contains("confidence"));
    }

    @Test
    void missingCandidatesField() {
        String mockResponse = "{}";
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.MALFORMED_RESPONSE, exception.getFailureType());
    }

    @Test
    void emptyCandidatesField() {
        String mockResponse = "{\"candidates\": []}";
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.MALFORMED_RESPONSE, exception.getFailureType());
    }

    @Test
    void missingContentField() {
        String mockResponse = "{\"candidates\": [{}]}";
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.MALFORMED_RESPONSE, exception.getFailureType());
    }

    @Test
    void missingPartsField() {
        String mockResponse = "{\"candidates\": [{\"content\": {}}]}";
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.MALFORMED_RESPONSE, exception.getFailureType());
    }

    @Test
    void emptyPartsField() {
        String mockResponse = "{\"candidates\": [{\"content\": {\"parts\": []}}]}";
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.MALFORMED_RESPONSE, exception.getFailureType());
    }

    @Test
    void missingPartTextField() {
        String mockResponse = "{\"candidates\": [{\"content\": {\"parts\": [{}]}}]}";
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.MALFORMED_RESPONSE, exception.getFailureType());
    }

    @Test
    void blankPartTextField() {
        String mockResponse = "{\"candidates\": [{\"content\": {\"parts\": [{\"text\": \"   \"}]}}]}";
        mockServer.expect(requestTo("/v1beta/models/gemini-2.5-flash:generateContent"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("x-goog-api-key", "mock-api-key"))
                .andRespond(withSuccess(mockResponse, MediaType.APPLICATION_JSON));

        AIServiceException exception = assertThrows(AIServiceException.class, () -> 
            geminiAIService.evaluate("Some query")
        );
        assertEquals(AIServiceException.FailureType.MALFORMED_RESPONSE, exception.getFailureType());
    }

    private String createGeminiResponseJson(String riskLevel, int riskScore, String category, double confidence, String reason) {
        return createGeminiResponseJsonText(
                String.valueOf(riskScore),
                "\"" + riskLevel + "\"",
                "\"" + category + "\"",
                String.valueOf(confidence),
                "\"" + reason + "\""
        );
    }

    private String createGeminiResponseJsonText(String riskScore, String riskLevel, String category, String confidence, String reason) {
        String contentText = String.format(
                "{\n  \"riskScore\": %s,\n  \"riskLevel\": %s,\n  \"threatCategory\": %s,\n  \"confidence\": %s,\n  \"reason\": %s\n}",
                riskScore, riskLevel, category, confidence, reason
        );

        String escapedText = contentText
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n");

        return "{\n" +
                "  \"candidates\": [\n" +
                "    {\n" +
                "      \"content\": {\n" +
                "        \"parts\": [\n" +
                "          {\n" +
                "            \"text\": \"" + escapedText + "\"\n" +
                "          }\n" +
                "        ]\n" +
                "      }\n" +
                "    }\n" +
                "  ]\n" +
                "}";
    }
}

package memoryguard_backend;

import memoryguard_backend.security.AiConfigProperties;
import memoryguard_backend.security.AIService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class AiConfigTests {

    @Autowired
    private AiConfigProperties aiConfigProperties;

    @Autowired
    private ApplicationContext applicationContext;

    @Test
    void propertiesShouldLoadCorrectly() {
        assertNotNull(aiConfigProperties);
        assertFalse(aiConfigProperties.isEnabled());
        assertEquals("gemini", aiConfigProperties.getProvider());
        assertEquals("gemini-2.5-flash", aiConfigProperties.getModel());
        assertEquals(1000, aiConfigProperties.getConnectTimeoutMs());
        assertEquals(3000, aiConfigProperties.getReadTimeoutMs());
        assertEquals(2000, aiConfigProperties.getMaxInputLength());
    }

    @Test
    void aiServiceBeanShouldBeRegistered() {
        assertTrue(applicationContext.containsBean("geminiAIService"));
        AIService aiService = applicationContext.getBean(AIService.class);
        assertNotNull(aiService);
    }

    @Test
    void contextShouldFailToLoadIfEnabledWithoutApiKey() {
        ApplicationContextRunner runner = new ApplicationContextRunner()
                .withUserConfiguration(MemoryguardBackendApplication.class)
                .withPropertyValues(
                        "spring.datasource.url=jdbc:postgresql://localhost:5432/memoryguard",
                        "spring.datasource.username=postgres",
                        "spring.datasource.password=041128",
                        "memoryguard.ai.enabled=true",
                        "memoryguard.ai.api-key="
                );

        runner.run(context -> {
            Throwable failure = context.getStartupFailure();
            assertNotNull(failure);
            
            // Check if startup failed due to IllegalStateException in properties validation
            boolean hasExpectedException = false;
            Throwable cause = failure;
            while (cause != null) {
                if (cause instanceof IllegalStateException && 
                    cause.getMessage().contains("AI Semantic Security Layer is enabled, but memoryguard.ai.api-key is missing!")) {
                    hasExpectedException = true;
                    break;
                }
                cause = cause.getCause();
            }
            assertTrue(hasExpectedException, "Expected IllegalStateException regarding missing API key, but got: " + failure);
        });
    }
}

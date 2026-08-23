package memoryguard_backend.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

@Configuration
public class SecurityAnalysisExecutorConfig {

    private final SecurityAnalysisProperties properties;

    public SecurityAnalysisExecutorConfig(SecurityAnalysisProperties properties) {
        this.properties = properties;
    }

    @Bean(destroyMethod = "shutdown")
    public ExecutorService securityAnalysisExecutor() {
        int poolSize = properties.getParallelism();
        return new ThreadPoolExecutor(
                poolSize,
                poolSize,
                0L, TimeUnit.MILLISECONDS,
                new LinkedBlockingQueue<>(1000)
        );
    }
}

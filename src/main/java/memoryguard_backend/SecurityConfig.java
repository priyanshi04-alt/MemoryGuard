package memoryguard_backend;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/health",
                    "/api/security-logs",
                    "/error"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.GET,
                    "/api/memories"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.GET,
                    "/api/memories/{id}/verify"
                ).permitAll()

                .requestMatchers(
                    HttpMethod.POST,
                    "/api/memories"
                ).permitAll()

                .anyRequest().authenticated()
            )
            .formLogin(form -> form.disable());

        return http.build();
    }
}
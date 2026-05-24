package com.cybervault.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable()) // Disable CSRF for API usage
            .authorizeHttpRequests(authz -> authz
                // Allow static resources
                .requestMatchers("/", "/index.html", "/static/**", "/favicon.ico",
                               "/logo.png", "/manifest.json", "/robots.txt").permitAll()

                // Allow API endpoints
                .requestMatchers("/api/**").permitAll()

                // Allow actuator endpoints
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()

                // Allow all other requests for now (can be restricted later)
                .anyRequest().permitAll()
            )
            .headers(headers -> headers.defaultsDisabled()
                .frameOptions().deny()
                .contentTypeOptions()
            );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow origins from environment variable or default
        String allowedOrigins = System.getenv("CORS_ORIGINS");
        if (allowedOrigins != null && !allowedOrigins.isEmpty()) {
            configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
        } else {
            // Default allowed origins for development and production
            configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",
                "https://cybervault-y26q.onrender.com",
                "https://*.onrender.com"
            ));
        }

        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
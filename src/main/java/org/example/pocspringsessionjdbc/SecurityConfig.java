package org.example.pocspringsessionjdbc;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.ForwardAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

import java.util.List;
import java.util.Map;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            SessionRegistry sessionRegistry,
            AuthenticationManager authenticationManager
    ) throws Exception {
        CompositeSessionAuthenticationStrategy authenticationStrategy = getAuthenticationStrategy(sessionRegistry);

        http
                .addFilterAfter(
                        new NewUsernamePasswordAuthenticationFilter(
                                "/auth/sign-in",
                                authenticationManager,
                                authenticationStrategy,
                                new ForwardAuthenticationSuccessHandler("/user/me"),
                                (request, response, exception) -> {
                                    ObjectMapper mapper = new ObjectMapper();
                                    response.setHeader("Content-Type", "application/json");
                                    if (exception instanceof SessionAuthenticationException) {
                                        response.setStatus(400);
                                        mapper.writeValue(response.getOutputStream(), Map.of(
                                                "message", "Maximum sessions exceeded"
                                        ));
                                        return;
                                    }
                                    if (exception instanceof BadCredentialsException) {
                                        response.setStatus(422);
                                        mapper.writeValue(response.getOutputStream(), Map.of(
                                                "message", "Invalid credentials"
                                        ));
                                        return;
                                    }
                                    response.setStatus(500);
                                }
                        ),
                        LogoutFilter.class
                )
                .csrf(AbstractHttpConfigurer::disable)
                .logout(logout -> logout
                        .logoutUrl("/auth/sign-out")
                        .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
                )
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .requestCache(conf -> {
                            HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
                            requestCache.setCreateSessionAllowed(false);
                            conf.requestCache(requestCache);
                        }
                )
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.NEVER)
                        .sessionAuthenticationStrategy(getAuthenticationStrategy(sessionRegistry))
                )
                .authorizeHttpRequests(req -> req
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/auth/sign-in", "/auth/sign-out").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    public SessionRegistry sessionRegistry(JdbcIndexedSessionRepository sessionRepository) {
        return new SpringSessionBackedSessionRegistry<>(sessionRepository);
    }

    private CompositeSessionAuthenticationStrategy getAuthenticationStrategy(SessionRegistry sessionRegistry) {
        ConcurrentSessionControlAuthenticationStrategy concurrentSessionControlStrategy = new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry);
        concurrentSessionControlStrategy.setMaximumSessions(1);
        concurrentSessionControlStrategy.setExceptionIfMaximumExceeded(true);

        RegisterSessionAuthenticationStrategy registerSessionStrategy = new RegisterSessionAuthenticationStrategy(sessionRegistry);

        return new CompositeSessionAuthenticationStrategy(List.of(
                concurrentSessionControlStrategy,
                registerSessionStrategy
        ));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.withUsername("eduardo")
                .password(passwordEncoder().encode("senha"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService);
        authenticationProvider.setPasswordEncoder(passwordEncoder);

        ProviderManager providerManager = new ProviderManager(authenticationProvider);
        providerManager.setEraseCredentialsAfterAuthentication(true);

        return providerManager;
    }
}

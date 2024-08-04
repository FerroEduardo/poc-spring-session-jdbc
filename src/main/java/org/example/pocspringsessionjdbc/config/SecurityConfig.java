package org.example.pocspringsessionjdbc.config;

import org.example.pocspringsessionjdbc.filter.CustomOAuthAuthenticationFilter;
import org.example.pocspringsessionjdbc.filter.CustomUsernamePasswordAuthenticationFilter;
import org.example.pocspringsessionjdbc.filter.DefaultAuthenticationFailureHandler;
import org.example.pocspringsessionjdbc.filter.RedirectAuthenticationSuccessHandler;
import org.example.pocspringsessionjdbc.service.GoogleOAuthService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            @Qualifier("oauth") AuthenticationManager oauthAuthenticationManager,
            SessionAuthenticationStrategy authenticationStrategy,
            GoogleOAuthService googleOAuthService
    ) throws Exception {
        var authenticationSuccessHandler = new RedirectAuthenticationSuccessHandler("/user/me");
        var authenticationFailureHandler = new DefaultAuthenticationFailureHandler();

        http
                .addFilterAfter(
                        new CustomUsernamePasswordAuthenticationFilter(
                                "/auth/sign-in",
                                authenticationManager,
                                authenticationStrategy,
                                authenticationSuccessHandler,
                                authenticationFailureHandler
                        ),
                        LogoutFilter.class
                )
                .addFilterAfter(
                        new CustomOAuthAuthenticationFilter(
                                "google",
                                oauthAuthenticationManager,
                                authenticationStrategy,
                                authenticationSuccessHandler,
                                authenticationFailureHandler,
                                googleOAuthService
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
                        .sessionAuthenticationStrategy(authenticationStrategy)
                )
                .authorizeHttpRequests(req -> req
                        .requestMatchers(
                                "/auth/sign-in",
                                "/auth/sign-out",
                                "/auth/sign-in/oauth/google",
                                "/auth/sign-in/oauth/google/callback"
                        ).permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean("noop")
    public PasswordEncoder noopPasswordEncoder() {
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                return "";
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return true;
            }
        };
    }
}

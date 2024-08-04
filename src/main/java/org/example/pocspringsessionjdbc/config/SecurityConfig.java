package org.example.pocspringsessionjdbc.config;

import org.example.pocspringsessionjdbc.filter.CustomAuthenticationFailureHandler;
import org.example.pocspringsessionjdbc.filter.CustomUsernamePasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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
import org.springframework.security.web.authentication.session.*;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http,
            AuthenticationManager authenticationManager,
            SessionAuthenticationStrategy authenticationStrategy
    ) throws Exception {

        http
                .addFilterAfter(
                        new CustomUsernamePasswordAuthenticationFilter(
                                "/auth/sign-in",
                                authenticationManager,
                                authenticationStrategy,
                                new ForwardAuthenticationSuccessHandler("/user/me"),
                                new CustomAuthenticationFailureHandler()
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
                        .requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/auth/sign-in", "/auth/sign-out").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}

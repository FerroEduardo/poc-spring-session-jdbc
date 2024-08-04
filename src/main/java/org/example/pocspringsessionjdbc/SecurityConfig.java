package org.example.pocspringsessionjdbc;

import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ConfigurationPropertiesAutoConfiguration configurationPropertiesAutoConfiguration) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(conf -> conf.defaultSuccessUrl("/me", true))
                .logout(Customizer.withDefaults())
                .headers(conf -> conf.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .sessionManagement(conf -> conf.sessionCreationPolicy(SessionCreationPolicy.NEVER))
                .authorizeHttpRequests(conf -> conf
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                );

        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
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
}

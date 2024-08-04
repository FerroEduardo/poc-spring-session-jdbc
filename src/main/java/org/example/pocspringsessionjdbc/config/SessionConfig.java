package org.example.pocspringsessionjdbc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.session.jdbc.JdbcIndexedSessionRepository;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;

import java.util.List;

@Configuration
public class SessionConfig {
    @Bean
    public SessionRegistry sessionRegistry(JdbcIndexedSessionRepository sessionRepository) {
        return new SpringSessionBackedSessionRegistry<>(sessionRepository);
    }

    @Bean
    public SessionAuthenticationStrategy getAuthenticationStrategy(SessionRegistry sessionRegistry) {
        ConcurrentSessionControlAuthenticationStrategy concurrentSessionControlStrategy = new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry);
        concurrentSessionControlStrategy.setMaximumSessions(1);
        concurrentSessionControlStrategy.setExceptionIfMaximumExceeded(true);

        RegisterSessionAuthenticationStrategy registerSessionStrategy = new RegisterSessionAuthenticationStrategy(sessionRegistry);

        return new CompositeSessionAuthenticationStrategy(List.of(
                concurrentSessionControlStrategy,
                registerSessionStrategy
        ));
    }
}

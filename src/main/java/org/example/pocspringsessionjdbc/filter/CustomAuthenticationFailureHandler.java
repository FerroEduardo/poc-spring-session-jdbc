package org.example.pocspringsessionjdbc.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;

import java.io.IOException;
import java.util.Map;

public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
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
}

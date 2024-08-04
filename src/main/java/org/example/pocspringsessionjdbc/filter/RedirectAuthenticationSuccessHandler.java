package org.example.pocspringsessionjdbc.filter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

public class RedirectAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private final String toRedirectUrl;

    public RedirectAuthenticationSuccessHandler(String toRedirectUrl) {
        this.toRedirectUrl = toRedirectUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.sendRedirect(toRedirectUrl);
    }
}

package org.example.pocspringsessionjdbc.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.pocspringsessionjdbc.service.GoogleOAuthService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.util.List;
import java.util.Map;

public class CustomOAuthAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final String provider;
    private final GoogleOAuthService googleOAuthService;

    public CustomOAuthAuthenticationFilter(
            String provider,
            AuthenticationManager authenticationManager,
            SessionAuthenticationStrategy authenticationStrategy,
            AuthenticationSuccessHandler successHandler,
            AuthenticationFailureHandler failureHandler,
            GoogleOAuthService googleOAuthService
    ) {
        super(String.format("/auth/sign-in/oauth/%s/callback", provider), authenticationManager);
        this.provider = provider;
        this.googleOAuthService = googleOAuthService;
        setAuthenticationSuccessHandler(successHandler);
        setAuthenticationFailureHandler(failureHandler);
        setSessionAuthenticationStrategy(authenticationStrategy);
        setSecurityContextRepository(new HttpSessionSecurityContextRepository());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // Invalidate current session if trying to log in
        var currentSession = request.getSession(false);
        if (currentSession != null) {
            currentSession.invalidate();
        }
        // Another option could be to redirect to homepage or
        // throw an error to prevent login with valid sessions

        if (provider.equals("google")) {
            String userCode = request.getParameter("code");
            Map<String, Object> profileDetails = googleOAuthService.getProfileDetails(userCode);
            if (profileDetails.get("verified_email") instanceof Boolean isEmailVerified) {
                if (!isEmailVerified) {
                    throw new AuthenticationServiceException("Email is not verified");
                }
                String email = profileDetails.get("email").toString();
//                String name = profileDetails.get("name").toString(); // given_name + family_name
                UsernamePasswordAuthenticationToken authRequest = UsernamePasswordAuthenticationToken.unauthenticated(email, "");
                setDetails(request, authRequest);
                return getAuthenticationManager().authenticate(authRequest);
            }
        }
        throw new AuthenticationServiceException("Invalid OAuth2 provider");
    }

    protected void setDetails(HttpServletRequest request, UsernamePasswordAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

}

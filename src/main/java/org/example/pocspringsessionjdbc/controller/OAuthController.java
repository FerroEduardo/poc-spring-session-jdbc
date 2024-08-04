package org.example.pocspringsessionjdbc.controller;

import org.example.pocspringsessionjdbc.service.GoogleOAuthService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.view.RedirectView;

@RestController
@RequestMapping("/auth/sign-in/oauth")
public class OAuthController {

    private final GoogleOAuthService googleOAuthService;

    public OAuthController(GoogleOAuthService googleOAuthService) {
        this.googleOAuthService = googleOAuthService;
    }

    @GetMapping("/google")
    public RedirectView signInGoogle() {
        return new RedirectView(googleOAuthService.getOauthLoginPage());
    }

}

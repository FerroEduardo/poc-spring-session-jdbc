package org.example.pocspringsessionjdbc.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class UserController {
    @RequestMapping("/user/me")
    public Map<String, Object> me(Authentication authentication) {
        return Map.of(
                "name", authentication.getName(),
                "details", authentication.getDetails(),
                "principal", authentication.getPrincipal()
        );
    }
}

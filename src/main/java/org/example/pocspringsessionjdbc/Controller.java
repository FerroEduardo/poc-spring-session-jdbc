package org.example.pocspringsessionjdbc;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class Controller {
    @GetMapping("/me")
    public Map<String, String> me(Authentication authentication) {
        return Map.of("name", authentication.getName());
    }
}

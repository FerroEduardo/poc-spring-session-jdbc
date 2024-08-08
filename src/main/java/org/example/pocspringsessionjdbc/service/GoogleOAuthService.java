package org.example.pocspringsessionjdbc.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Service
public class GoogleOAuthService {

    private final String clientId;
    private final String clientSecret;
    private final String redirectUri;
    private final List<String> scopes;

    public GoogleOAuthService(
            @Value("${oauth.google.client-id}") String clientId,
            @Value("${oauth.google.client-secret}") String clientSecret,
            @Value("${oauth.google.redirect-uri}") String redirectUri,
            @Value("${oauth.google.scopes}") List<String> scopes
    ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
    }

    public String getOauthLoginPage() {
        return String.format(
                "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=%s&response_type=code&client_id=%s&scope=%s&access_type=offline&prompt=consent",
                redirectUri, clientId, String.join("+", scopes)
        );
    }

    public Map<String, Object> getProfileDetails(String userCode) {
        String accessToken = getAccessToken(userCode);

        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(accessToken);

        HttpEntity<String> requestEntity = new HttpEntity<>(httpHeaders);
        String url = "https://www.googleapis.com/oauth2/v2/userinfo";
        ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.GET, requestEntity, String.class);

        try {
            ObjectMapper mapper = new ObjectMapper();
            return mapper.readValue(response.getBody(), Map.class);
        } catch (IOException e) {
            throw new BadCredentialsException("Invalid credentials");
        }
    }

    private String getAccessToken(String code) {
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("code", code);
        params.add("redirect_uri", redirectUri);
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        for (String scope : scopes) {
            params.add("scope", scope);
        }
        params.add("grant_type", "authorization_code");

        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, httpHeaders);
        String url = "https://oauth2.googleapis.com/token";

        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> map = mapper.readValue(restTemplate.postForObject(url, requestEntity, String.class), Map.class);

            return map.get("access_token").toString();
        } catch (IOException e) {
            throw new BadCredentialsException("Invalid credentials");
        }
    }
}

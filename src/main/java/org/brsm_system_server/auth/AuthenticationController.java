package org.brsm_system_server.auth;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.GrantedAuthority;


import java.util.Map;


@CrossOrigin(origins = "http://127.0.0.1:8081", allowCredentials = "true", allowedHeaders = "Content-Type, Authorization")
@RestController
@RequestMapping("/brsm/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    @PostMapping("/signUp")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(service.authenticate(request));
    }


    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized"));
        }

        String role = authentication.getAuthorities()
                .stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .orElse("UNKNOWN");

        return ResponseEntity.ok(Map.of(
                "role", role
        ));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            SecurityContextHolder.clearContext();
            logger.info("User logged out: {}", authentication.getName());
        }
        return ResponseEntity.ok().build();
    }
}
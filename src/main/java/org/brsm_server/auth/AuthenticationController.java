package org.brsm_server.auth;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.Map;

@RestController
@RequestMapping("/brsm/auth")
@RequiredArgsConstructor
@CrossOrigin(
        origins = "http://127.0.0.1:8081",
        allowCredentials = "true",
        allowedHeaders = "*"
)
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @PostMapping("/sign-up")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authenticationService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(
            @RequestBody RefreshRequest request) {

        return ResponseEntity.ok(authenticationService.refresh(request.getRefreshToken()));
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
    public ResponseEntity<Void> logout(HttpServletRequest request, @RequestBody RefreshRequest refreshRequest) {
        return authenticationService.logout(request, refreshRequest);
    }
}
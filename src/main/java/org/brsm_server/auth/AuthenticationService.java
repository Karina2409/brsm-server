package org.brsm_server.auth;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import org.brsm_server.entity.Student;
import org.brsm_server.entity.User;
import org.brsm_server.entity.enums.RoleEnum;
import org.brsm_server.exception.EntityExistsException;
import org.brsm_server.exception.InvalidTokenException;
import org.brsm_server.repository.StudentRepository;
import org.brsm_server.repository.UserRepository;
import org.brsm_server.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.brsm_server.security.token.TokenBlacklistService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final StudentRepository studentRepository;
    private final TokenBlacklistService blacklistService;

    public AuthenticationResponse register(RegisterRequest request) {
        if (repository.findByLogin(request.getLogin()).isPresent()) {
            throw new EntityExistsException("User already exists");
        }

        RoleEnum role = parseRole(request.getRole());

        Student student = new Student();

        Student savedStudent = studentRepository.save(student);

        User user = User.builder()
                .login(request.getLogin())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .student(savedStudent)
                .build();

        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .id(user.getUserId())
                .role(user.getRole().name())
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getLogin(),
                        request.getPassword()
                )
        );
        User user = repository.findByLogin(request.getLogin())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        return AuthenticationResponse.builder()
                .token(accessToken)
                .refreshToken(refreshToken)
                .id(user.getUserId())
                .role(user.getRole().name())
                .build();
    }

    public AuthenticationResponse refresh(String refreshToken) {

        String username = jwtService.extractUsername(refreshToken);

        User user = repository.findByLogin(username)
                .orElseThrow();

        if (!jwtService.isTokenValid(refreshToken, user)) {
            throw new InvalidTokenException("Invalid refresh token");
        }

        String newAccessToken = jwtService.generateAccessToken(user);

        return AuthenticationResponse.builder()
                .token(newAccessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public ResponseEntity<Void> logout(HttpServletRequest request, RefreshRequest refreshRequest) {
        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            Date expiry = jwtService.extractClaim(token, Claims::getExpiration);
            blacklistService.blacklist(token, expiry);
        }

        if (refreshRequest.getRefreshToken() != null) {
            String refreshToken = refreshRequest.getRefreshToken();
            Date expiry = jwtService.extractClaim(refreshToken, Claims::getExpiration);
            blacklistService.blacklist(refreshToken, expiry);
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            SecurityContextHolder.clearContext();
        }

        return ResponseEntity.ok().build();
    }

    private RoleEnum parseRole(RoleEnum role) {
        if (role == null) return RoleEnum.STUDENT;
        return role;
    }
}
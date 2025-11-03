package com.brsm.securityservice.service;

import com.brsm.securityservice.dto.LoginRequest;
import com.brsm.securityservice.dto.RegisterRequest;
import com.brsm.securityservice.entity.Role;
import com.brsm.securityservice.entity.User;
import com.brsm.securityservice.repository.UserRepository;
import com.brsm.securityservice.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public String createUser(RegisterRequest request) {
        User user = new User();
        user.setLogin(request.getLogin());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.STUDENT);
        user.setStudentId(request.getStudentId());

        userRepository.save(user);
        return "User registered successfully";
    }

    public String login(LoginRequest request) {
        User user = userRepository.findByLogin(request.getLogin())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid credentials");
        }

        return jwtService.generateToken(user.getLogin(), user.getRole().name(), user.getStudentId());
    }

}

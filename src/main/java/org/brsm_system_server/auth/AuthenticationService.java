package org.brsm_system_server.auth;

import org.brsm_system_server.entity.Student;
import org.brsm_system_server.entity.User;
import org.brsm_system_server.entity.enums.RoleEnum;
import org.brsm_system_server.help.ImageUtil;
import org.brsm_system_server.repository.StudentRepository;
import org.brsm_system_server.repository.UserRepository;
import org.brsm_system_server.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final StudentRepository studentRepository;

    public AuthenticationResponse register(RegisterRequest request) {
        RoleEnum role = request.getRole() != null ? RoleEnum.valueOf(String.valueOf(request.getRole())) : RoleEnum.STUDENT;

        String defaultPhotoPath = "D:/BRSM project/BRSM-Project/frontend/assets/icons/photo.png";
        byte[] imageBytes;
        try {
            imageBytes = ImageUtil.imageToByteArray(defaultPhotoPath);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        Student student = new Student();
        student.setImage(imageBytes);

        Student savedStudent = studentRepository.save(student);

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .student(savedStudent)
                .build();

        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        User user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .id(user.getUserId())
                .role(user.getRole().name())
                .build();
    }
}
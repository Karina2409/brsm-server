package org.brsm_server.service.impl;

import lombok.RequiredArgsConstructor;
import org.brsm_server.entity.Student;
import org.brsm_server.entity.User;
import org.brsm_server.entity.enums.RoleEnum;
import org.brsm_server.repository.*;
import org.brsm_server.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public Student findStudentById(Long id) {
        User userP = userRepository.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return userP.getStudent();
    }

    @Override
    @Transactional
    public void changeUserRole(Long userId, RoleEnum newRole) {
        User user = userRepository.findById(userId).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        RoleEnum currentRole = user.getRole();

        if (currentRole == newRole) {
            return;
        }

        user.setRole(newRole);
        userRepository.save(user);
    }
}

package org.brsm_server.service;

import org.brsm_server.entity.Student;
import org.brsm_server.entity.User;

import java.util.List;

public interface UserService {
    List<User> findAllUsers();
    Student findStudentById(Long id);
//    void changeUserRole(Long userId, RoleEnum newRole);
}

package org.brsm_server.service;

import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.User;
import org.brsm_server.entity.enums.RoleEnum;

import java.util.List;

public interface UserService {
    List<User> findAllUsers();
    StudentDTO findStudentById(Long id);
    void changeUserRole(Long userId, RoleEnum newRole, boolean force);
}

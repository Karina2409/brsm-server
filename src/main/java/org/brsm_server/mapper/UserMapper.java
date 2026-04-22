package org.brsm_server.mapper;

import org.brsm_server.dto.UserDTO;
import org.brsm_server.entity.Student;
import org.brsm_server.entity.User;
import org.brsm_server.service.UserService;

public class UserMapper {

    public static UserDTO toDTO(User user, UserService userService) {
        Student student;

        student = userService.findStudentById(user.getUserId());

        return new UserDTO(
                user.getUserId(),
                student.getLastName(),
                student.getFirstName(),
                student.getPatronymic(),
                user.getRole()
        );
    }
}

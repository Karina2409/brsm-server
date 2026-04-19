package org.brsm_system_server.mapper;

import org.brsm_system_server.dto.UserDTO;
import org.brsm_system_server.entity.Secretary;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.entity.User;
import org.brsm_system_server.entity.enums.RoleEnum;
import org.brsm_system_server.service.interfaces.IUserService;

public class UserMapper {

    public static UserDTO toDTO(User user, IUserService userService) {
        Student student;
        Secretary secretary;

        if (user.getRole() == RoleEnum.STUDENT){
            student = userService.findStudentById(user.getUserId());

            return new UserDTO(
                    user.getUserId(),
                    student.getLastName(),
                    student.getFirstName(),
                    student.getMiddleName(),
                    user.getRole()
            );
        }
        else {
            secretary = userService.findSecretaryById(user.getUserId());

            return new UserDTO(
                    user.getUserId(),
                    secretary.getLastName(),
                    secretary.getFirstName(),
                    secretary.getMiddleName(),
                    user.getRole()
            );
        }

    }

}

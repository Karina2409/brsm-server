package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.brsm_server.entity.enums.Faculty;
import org.brsm_server.entity.enums.RoleEnum;

import java.time.OffsetDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private Long userId;
    private String login;
    private String surname;
    private String name;
    private String patronymic;
    private RoleEnum role;
    private OffsetDateTime lastLogin;
    private String groupNumber;
    private Faculty faculty;
}

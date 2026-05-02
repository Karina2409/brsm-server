package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.brsm_server.entity.enums.RoleEnum;

import java.time.OffsetDateTime;

@Data
@AllArgsConstructor
public class UserDTO {
    private Long userId;
    private String login;
    private String surname;
    private String name;
    private String patronymic;
    private RoleEnum role;
    private OffsetDateTime lastLogin;
}

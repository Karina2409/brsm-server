package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.brsm_server.entity.enums.RoleEnum;

@Data
@AllArgsConstructor
public class UserDTO {
    private Long userId;
    private String lastName;
    private String firstName;
    private String patronymic;
    private RoleEnum role;
}

package org.brsm_system_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.brsm_system_server.entity.enums.RoleEnum;

@Data
@AllArgsConstructor
public class UserDTO {
    private Long id;
    private String lastName;
    private String firstName;
    private String middleName;
    private RoleEnum role;
}

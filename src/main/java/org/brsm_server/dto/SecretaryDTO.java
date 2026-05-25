package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.brsm_server.entity.enums.Faculty;
import org.brsm_server.entity.enums.RoleEnum;

@Data
@AllArgsConstructor
public class SecretaryDTO {
    private String surname;
    private String name;
    private String patronymic;
    private Faculty faculty;
    private String telegramUsername;
    private byte[] photo;
    private RoleEnum role;
}

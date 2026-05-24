package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.brsm_server.entity.enums.Faculty;

import java.time.LocalDate;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class CreateStudentRequestDTO {
    private String login;
    private String surname;
    private String name;
    private String patronymic;
    private String fullNameDative;
    private String groupNumber;
    private Faculty faculty;
    private LocalDate dateOfBirth;
    private String email;
    private String telegramUsername;
    private String phoneNumber;
    private boolean dormitoryResidence;
    private String dormBlockNumber;
    private Integer dormNumber;
    private boolean brsmMember;
    private byte[] photo;
}

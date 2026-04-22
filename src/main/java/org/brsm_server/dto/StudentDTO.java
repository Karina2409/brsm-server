package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.brsm_server.entity.enums.Faculty;

@Data
@AllArgsConstructor
public class StudentDTO {
    private Long studentId;
    private String fullNameDative;
    private String lastName;
    private String firstName;
    private String patronymic;
    private String groupNumber;
    private Faculty faculty;
    private boolean dormitoryResidence;
    private String dormBlockNumber;
    private Integer dormNumber;
    private Integer eventCount;
    private boolean isBrsmMember;
    private String phoneNumber;
    private String telegramUsername;
    private byte[] photo;
}

package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class StudentFullNameDTO {
    private Long studentId;
    private String surname;
    private String name;
    private String patronymic;
    private String groupNumber;
    private boolean brsmMember;
}

package org.brsm_system_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.brsm_system_server.entity.enums.FacultyEnum;

@Data
@AllArgsConstructor
public class StudentDTO {
    private Long studentId;
    private String studentFullNameD;
    private String lastName;
    private String firstName;
    private String middleName;
    private String groupNumber;
    private FacultyEnum studentFaculty;
    private boolean dormitoryResidence;
    private String dormBlockNumber;
    private Integer dormNumber;
    private Integer eventCount;
    private boolean isBrsmMember;
    private String phoneNumber;
    private String telegram;
    private byte[] image;
}

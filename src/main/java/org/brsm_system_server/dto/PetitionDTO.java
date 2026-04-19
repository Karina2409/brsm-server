package org.brsm_system_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.brsm_system_server.entity.enums.FacultyEnum;

import java.util.Date;

@Data
@AllArgsConstructor
public class PetitionDTO {
    private Long petitionId;
    private String petitionName;
    private Date petitionDate;
    private FacultyEnum studentFaculty;
    private String studentLastName;
}

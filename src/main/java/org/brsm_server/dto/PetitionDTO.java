package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.brsm_server.entity.enums.Faculty;

import java.util.Date;

@Data
@AllArgsConstructor
public class PetitionDTO {
    private Long petitionId;
    private String petitionName;
    private Date petitionDate;
    private Faculty studentFaculty;
    private String studentLastName;
}

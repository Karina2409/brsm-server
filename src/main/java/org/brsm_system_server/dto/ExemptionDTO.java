package org.brsm_system_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.brsm_system_server.entity.enums.FacultyEnum;

import java.util.Date;

@Data
@AllArgsConstructor
public class ExemptionDTO {
    private Long exemptionId;
    private String exemptionName;
    private Date exemptionDate;
    private FacultyEnum studentsFacultyExemption;
    private String eventName;
}

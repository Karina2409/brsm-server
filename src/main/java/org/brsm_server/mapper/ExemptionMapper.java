package org.brsm_server.mapper;

import org.brsm_server.dto.ExemptionDTO;
import org.brsm_server.entity.Exemption;

public class ExemptionMapper {
    public static ExemptionDTO toDto(Exemption exemption) {
        return new ExemptionDTO(
                exemption.getExemptionId(),
                exemption.getExemptionName(),
                exemption.getExemptionDate(),
                exemption.getStudentsFacultyExemption(),
                exemption.getEventName()
        );
    }
}

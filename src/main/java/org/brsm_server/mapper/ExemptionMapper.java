package org.brsm_server.mapper;

import org.brsm_server.dto.ExemptionDTO;
import org.brsm_server.entity.Exemption;

import java.util.Date;

public class ExemptionMapper {
    public static ExemptionDTO toDto(Exemption exemption) {
        return new ExemptionDTO(
                exemption.getExemptionId(),
                exemption.getName(),
                Date.from(exemption.getCreatedAt().toInstant()),
                exemption.getStudentsFaculty(),
                exemption.getEventName()
        );
    }
}

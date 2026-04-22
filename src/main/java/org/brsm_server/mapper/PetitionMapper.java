package org.brsm_server.mapper;

import org.brsm_server.dto.PetitionDTO;
import org.brsm_server.entity.Petition;

import java.util.Date;

public class PetitionMapper {
    public static PetitionDTO toDto(Petition petition) {
        return new PetitionDTO(
                petition.getPetitionId(),
                petition.getName(),
                Date.from(petition.getCreatedAt().toInstant()),
                petition.getStudentFaculty(),
                petition.getStudentLastName()
        );
    }
}

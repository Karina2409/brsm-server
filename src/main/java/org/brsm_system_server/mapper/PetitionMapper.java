package org.brsm_system_server.mapper;

import org.brsm_system_server.dto.PetitionDTO;
import org.brsm_system_server.entity.Petition;

public class PetitionMapper {
    public static PetitionDTO toDto(Petition petition) {
        return new PetitionDTO(
                petition.getPetitionId(),
                petition.getPetitionName(),
                petition.getPetitionDate(),
                petition.getStudentFacultyPetition(),
                petition.getStudentLastName()
        );
    }
}

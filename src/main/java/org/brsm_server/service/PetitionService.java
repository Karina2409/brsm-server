package org.brsm_server.service;

import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.Petition;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface PetitionService {

    List<Petition> getAllPetitions();
    Petition savePetition(Long studentId);
    ResponseEntity<Void> deletePetitionById(Long id);
    byte[] downloadPetition(Long petitionId);
    List<StudentDTO> getEligibleStudentsToPetition();
}

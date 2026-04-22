package org.brsm_server.service;

import org.brsm_server.entity.Petition;
import org.brsm_server.entity.Student;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface PetitionService {

    List<Petition> getAllPetitions();
    Petition savePetition(Long studentId);
    ResponseEntity<Void> deletePetitionById(Long id);
    void downloadPetition(Long petitionId);
    List<Student> getEligibleStudentsToPetition();
}

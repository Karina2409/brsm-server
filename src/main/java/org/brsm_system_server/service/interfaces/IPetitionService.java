package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Petition;
import org.brsm_system_server.entity.Student;
import org.springframework.http.ResponseEntity;

import java.util.List;

public interface IPetitionService {

    List<Petition> getAllPetitions();
    Petition savePetition(Long studentId);
    ResponseEntity<Void> deletePetitionById(Long id);
    void downloadPetition(Long petitionId);
    List<Student> getEligibleStudentsToPetition();
}

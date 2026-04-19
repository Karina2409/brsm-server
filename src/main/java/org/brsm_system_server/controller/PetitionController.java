package org.brsm_system_server.controller;

import org.brsm_system_server.dto.PetitionDTO;
import org.brsm_system_server.entity.Petition;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.mapper.PetitionMapper;
import org.brsm_system_server.service.interfaces.IPetitionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/petitions")
public class PetitionController {

    @Autowired
    private IPetitionService petitionService;

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/get-all")
    public List<PetitionDTO> getPetitions(){
        List<Petition> petitions = petitionService.getAllPetitions();
        return petitions.stream().map(PetitionMapper::toDto).toList();
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PostMapping("/post/{studentId}")
    public ResponseEntity<Petition> createPetition(@PathVariable("studentId") Long studentId){
        Petition savedPetition = petitionService.savePetition(studentId);
        return ResponseEntity.ok(savedPetition);
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @DeleteMapping("/delete/{petitionId}")
    public ResponseEntity<Void> deletePetition(@PathVariable("petitionId") Long petitionId){
        return petitionService.deletePetitionById(petitionId);
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PostMapping("/download/{petitionId}")
    public void downloadPetition(@PathVariable Long petitionId){
        petitionService.downloadPetition(petitionId);
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/eligible")
    public List<Student> getEligibleStudents() {
        return petitionService.getEligibleStudentsToPetition();
    }

}

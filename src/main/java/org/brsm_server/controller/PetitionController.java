package org.brsm_server.controller;

import lombok.RequiredArgsConstructor;
import org.brsm_server.dto.PetitionDTO;
import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.Petition;
import org.brsm_server.mapper.PetitionMapper;
import org.brsm_server.security.Roles;
import org.brsm_server.service.PetitionService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/petitions")
@RequiredArgsConstructor
public class PetitionController {

    private final PetitionService petitionService;
    private final PetitionMapper petitionMapper;

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping
    public List<PetitionDTO> getPetitions(){
        List<Petition> petitions = petitionService.getAllPetitions();
        return petitions.stream().map(petitionMapper::toDto).toList();
    }

    @PreAuthorize(Roles.SECRETARIES)
    @PostMapping("/{studentId}")
    public ResponseEntity<PetitionDTO> createPetition(@PathVariable("studentId") Long studentId){
        Petition savedPetition = petitionService.savePetition(studentId);
        return ResponseEntity.ok(petitionMapper.toDto(savedPetition));
    }

    @PreAuthorize(Roles.SECRETARIES)
    @DeleteMapping("/{petitionId}")
    public ResponseEntity<Void> deletePetition(@PathVariable("petitionId") Long petitionId){
        return petitionService.deletePetitionById(petitionId);
    }

    @PreAuthorize(Roles.SECRETARIES)
    @PostMapping("/download/{petitionId}")
    public ResponseEntity<byte[]> downloadPetition(@PathVariable Long petitionId){
        byte[] pdfContents = petitionService.downloadPetition(petitionId);

        if (pdfContents == null || pdfContents.length == 0) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"petition_" + petitionId + ".pdf\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdfContents);
    }

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping("/eligible")
    public List<StudentDTO> getEligibleStudents() {
        return petitionService.getEligibleStudentsToPetition();
    }

}

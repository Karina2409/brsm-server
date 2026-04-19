package org.brsm_system_server.controller;

import org.brsm_system_server.service.StudentImportService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@CrossOrigin(origins = "http://127.0.0.1:8081", allowedHeaders = {"*", "Content-Type, Authorization"}, methods = {RequestMethod.DELETE, RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT}, allowCredentials = "true")
@RequestMapping("/students")
public class StudentImportController {

    private final StudentImportService studentImportService;

    public StudentImportController(StudentImportService studentImportService) {
        this.studentImportService = studentImportService;
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PostMapping("/import")
    public ResponseEntity<String> importStudents(@RequestParam("file") MultipartFile file) {
        try {
            studentImportService.importStudents(file);
            return ResponseEntity.status(HttpStatus.OK).body("Students imported successfully.");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error importing students: " + e.getMessage());
        }
    }
}


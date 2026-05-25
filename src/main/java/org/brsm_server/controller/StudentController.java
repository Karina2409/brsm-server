package org.brsm_server.controller;

import lombok.RequiredArgsConstructor;
import org.brsm_server.dto.*;
import org.brsm_server.entity.Student;
import org.brsm_server.mapper.EventMapper;
import org.brsm_server.mapper.StudentMapper;
import org.brsm_server.security.Roles;
import org.brsm_server.service.EventService;
import org.brsm_server.service.StudentService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/students")
@RequiredArgsConstructor
public class StudentController {

    private final StudentService studentService;
    private final EventService eventService;
    private final EventMapper eventMapper;
    private final StudentMapper studentMapper;

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping
    public List<StudentDTO> getStudents() {
        return studentService.findAllStudentsAndSecretaries()
                .stream()
                .map(studentMapper::toDto)
                .toList();
    }

    @PreAuthorize(Roles.ALL_AUTH)
    @GetMapping("/{studentId}")
    public StudentDTO getStudentById(@PathVariable Long studentId){
        return studentMapper.toDto(studentService.getStudentById(studentId));
    }

    @PreAuthorize(Roles.ALL_AUTH)
    @GetMapping("/{studentId}/events")
    public List<EventDTO> getEventsByStudentId(@PathVariable Long studentId) {
        return eventService.getEventsByStudentId(studentId)
                .stream()
                .map(eventMapper::toDto)
                .toList();
    }

    @PreAuthorize(Roles.ALL_AUTH)
    @PutMapping("/{studentId}")
    public StudentDTO updateStudent(@PathVariable Long studentId, @RequestBody StudentDTO dto) {
        Student updated = studentService.updateStudent(studentId, dto);
        return studentMapper.toDto(updated);
    }

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping("/statistics/by-faculty")
    public List<FacultyStatisticsDTO> getStudentCountByFaculty() {
        return studentService.getStudentCountByFaculty();
    }

    @PreAuthorize(Roles.SECRETARIES)
    @PostMapping
    public StudentDTO createStudent(@RequestBody CreateStudentRequestDTO request) {
        return studentMapper.toDto(studentService.createStudentWithUser(request));
    }

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping("/only-students")
    public List<StudentDTO> getOnlyStudents() {
        return studentService.findAllOnlyStudents()
                .stream()
                .map(studentMapper::toDto)
                .toList();
    }

    @PreAuthorize(Roles.STUDENT)
    @GetMapping("/only-secretaries")
    public List<SecretaryDTO> getOnlySecretaries() {
        return studentService.findAllOnlySecretaries()
                .stream()
                .map(studentMapper::toSecretaryDto)
                .toList();
    }
}

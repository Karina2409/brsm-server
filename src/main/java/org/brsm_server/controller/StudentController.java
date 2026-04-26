package org.brsm_server.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.brsm_server.dto.EventDTO;
import org.brsm_server.dto.StudentDTO;
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
@Slf4j
@CrossOrigin(origins = "http://127.0.0.1:8081", allowedHeaders = {"*", "Content-Type, Authorization"}, methods = {RequestMethod.DELETE, RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT}, allowCredentials = "true")
@RequiredArgsConstructor
public class StudentController {

    private final StudentService studentService;
    private final EventService eventService;
    private final EventMapper eventMapper;
    private final StudentMapper studentMapper;

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping
    public List<StudentDTO> getStudents() {
        return studentService.findAllStudents()
                .stream()
                .map(studentMapper::toDto)
                .toList();
    }

    @PreAuthorize(Roles.SECRETARIES)
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
}

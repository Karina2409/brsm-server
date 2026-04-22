package org.brsm_server.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.brsm_server.dto.EventDTO;
import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.Event;
import org.brsm_server.entity.Student;
import org.brsm_server.mapper.EventMapper;
import org.brsm_server.mapper.StudentMapper;
import org.brsm_server.service.EventService;
import org.brsm_server.service.StudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/students")
@Slf4j
@CrossOrigin(origins = "http://127.0.0.1:8081", allowedHeaders = {"*", "Content-Type, Authorization"}, methods = {RequestMethod.DELETE, RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT}, allowCredentials = "true")
@RequiredArgsConstructor
public class StudentController {

    @Autowired
    private StudentService studentService;

    @Autowired
    private EventService eventService;

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/get-all")
    public List<StudentDTO> getStudents() {
        List<Student> students = studentService.findAllStudents();
        return students.stream().map(student -> {
            return StudentMapper.toDto(student, eventService);
        }).toList();
    }

    @GetMapping("/{studentId}")
    public StudentDTO getStudentById(@PathVariable Long studentId){
        Student student = studentService.getStudentById(studentId);
        return StudentMapper.toDto(student, eventService);
    }


    @GetMapping("/{studentId}/events")
    public List<EventDTO> getEventsByStudentId(@PathVariable Long studentId) {
        List<Event> events = eventService.getEventsByStudentId(studentId);
        return events.stream().map(EventMapper::toDto).toList();
    }

    @PreAuthorize("hasAuthority('STUDENT')")
    @PutMapping("/student/{studentId}")
    public ResponseEntity<?> updateStudent(@PathVariable Long studentId, @RequestBody Student updateStudent) {
        Student student = studentService.getStudentById(studentId);
        if (student != null) {
            student.setLastName(updateStudent.getLastName());
            student.setFirstName(updateStudent.getFirstName());
            student.setPatronymic(updateStudent.getPatronymic());
            student.setGroupNumber(updateStudent.getGroupNumber());
            student.setFaculty(updateStudent.getFaculty());
            student.setPhoneNumber(updateStudent.getPhoneNumber());
            student.setTelegramUsername(updateStudent.getTelegramUsername());
            student.setDormitoryResidence(updateStudent.isDormitoryResidence());
            student.setDormBlockNumber(updateStudent.getDormBlockNumber());
            student.setDormNumber(updateStudent.getDormNumber());
            student.setFullNameDative(updateStudent.getFullNameDative());

            if (updateStudent.getPhoto() != null && updateStudent.getPhoto().length > 0) {
                student.setPhoto(updateStudent.getPhoto());
            }

            studentService.createStudent(student);
            return ResponseEntity.ok(student);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Студент с указанным айди не найден");
        }
    }
}

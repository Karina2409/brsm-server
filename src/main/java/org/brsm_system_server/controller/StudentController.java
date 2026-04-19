package org.brsm_system_server.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.brsm_system_server.dto.EventDTO;
import org.brsm_system_server.dto.StudentDTO;
import org.brsm_system_server.entity.Event;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.help.ImageUtil;
import org.brsm_system_server.mapper.EventMapper;
import org.brsm_system_server.mapper.StudentMapper;
import org.brsm_system_server.service.interfaces.IEventService;
import org.brsm_system_server.service.interfaces.IStudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/students")
@Slf4j
@CrossOrigin(origins = "http://127.0.0.1:8081", allowedHeaders = {"*", "Content-Type, Authorization"}, methods = {RequestMethod.DELETE, RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT}, allowCredentials = "true")
@RequiredArgsConstructor
public class StudentController {

    @Autowired
    private IStudentService studentService;

    @Autowired
    private IEventService eventService;

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
            student.setMiddleName(updateStudent.getMiddleName());
            student.setGroupNumber(updateStudent.getGroupNumber());
            student.setStudentFaculty(updateStudent.getStudentFaculty());
            student.setPhoneNumber(updateStudent.getPhoneNumber());
            student.setTelegram(updateStudent.getTelegram());
            student.setDormitoryResidence(updateStudent.isDormitoryResidence());
            student.setDormBlockNumber(updateStudent.getDormBlockNumber());
            student.setDormNumber(updateStudent.getDormNumber());
            student.setStudentFullNameD(updateStudent.getStudentFullNameD());

            if (updateStudent.getImage() != null && updateStudent.getImage().length > 0) {
                student.setImage(updateStudent.getImage());
            }

            studentService.createStudent(student);
            return ResponseEntity.ok(student);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Студент с указанным айди не найден");
        }
    }
}

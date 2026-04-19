package org.brsm_system_server.service;

import org.brsm_system_server.entity.Student;
import org.brsm_system_server.repository.StudentRepository;
import org.brsm_system_server.service.interfaces.IEventService;
import org.brsm_system_server.service.interfaces.IStudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class StudentService implements IStudentService {

    @Autowired
    private StudentRepository studentRepository;

    @Autowired
    private IEventService eventService;

    @Override
    public List<Student> findAllStudents(){
        return studentRepository.findAll();
    }

    @Override
    public Student getStudentById(Long id){
        Optional<Student> optionalStudent = studentRepository.findById(id);
        return optionalStudent.orElse(null);
    }

    @Override
    public List<Student> getStudentsByEventId(Long eventId) {
        return studentRepository.findStudentsByEventId(eventId);
    }

    @Override
    public List<Student> findEligibleStudents() {
        List<Student> allStudents = studentRepository.findAll();
        return allStudents.stream()
                .filter(student -> eventService.getEventByStudentIdPetition(student.getStudentId()).size() >= 5)
                .collect(Collectors.toList());
    }

    @Override
    public Student createStudent(Student student) {
        return studentRepository.save(student);
    }
}

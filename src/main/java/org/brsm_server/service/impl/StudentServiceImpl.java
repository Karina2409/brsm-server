package org.brsm_server.service.impl;

import lombok.RequiredArgsConstructor;
import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.Student;
import org.brsm_server.repository.StudentRepository;
import org.brsm_server.service.EventService;
import org.brsm_server.service.StudentService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@RequiredArgsConstructor
public class StudentServiceImpl implements StudentService {

    private final StudentRepository studentRepository;
    private final EventService eventService;

    @Override
    public List<Student> findAllStudents(){
        return studentRepository.findAll();
    }

    @Override
    public Student getStudentById(Long id) {
        return studentRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @Override
    public List<Student> getStudentsByEventId(Long eventId) {
        return studentRepository.findStudentsByEventId(eventId);
    }

    @Override
    public List<Student> findEligibleStudents() {
        return studentRepository.findAll()
                .stream()
                .filter(s -> eventService.getEventByStudentIdPetition(s.getStudentId()).size() >= 5)
                .toList();
    }

    @Override
    public Student createStudent(Student student) {
        return studentRepository.save(student);
    }

    @Override
    public Student updateStudent(Long id, StudentDTO dto) {
        Student student = getStudentById(id);

        student.setLastName(dto.getLastName());
        student.setFirstName(dto.getFirstName());
        student.setPatronymic(dto.getPatronymic());
        student.setGroupNumber(dto.getGroupNumber());
        student.setFaculty(dto.getFaculty());
        student.setPhoneNumber(dto.getPhoneNumber());
        student.setTelegramUsername(dto.getTelegramUsername());
        student.setDormitoryResidence(dto.isDormitoryResidence());
        student.setDormBlockNumber(dto.getDormBlockNumber());
        student.setDormNumber(dto.getDormNumber());
        student.setFullNameDative(dto.getFullNameDative());

        if (dto.getPhoto() != null && dto.getPhoto().length > 0) {
            student.setPhoto(dto.getPhoto());
        }

        return studentRepository.save(student);
    }
}

package org.brsm_server.service.impl;

import lombok.RequiredArgsConstructor;
import org.brsm_server.dto.CreateStudentRequestDTO;
import org.brsm_server.dto.FacultyStatisticsDTO;
import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.Student;
import org.brsm_server.entity.User;
import org.brsm_server.entity.enums.Faculty;
import org.brsm_server.entity.enums.RoleEnum;
import org.brsm_server.exception.EntityExistsException;
import org.brsm_server.mapper.StudentMapper;
import org.brsm_server.repository.StudentRepository;
import org.brsm_server.repository.UserRepository;
import org.brsm_server.service.EventService;
import org.brsm_server.service.StudentService;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Service
@RequiredArgsConstructor
public class StudentServiceImpl implements StudentService {

    private final StudentRepository studentRepository;
    private final EventService eventService;
    private final UserRepository userRepository;
    private final StudentMapper studentMapper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public List<Student> findAllStudentsAndSecretaries(){
        return studentRepository.findAll();
    }

    @Override
    public Student getStudentById(Long id) {
        return studentRepository.findWithEventsByStudentId(id)
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
    public Student updateStudent(Long id, StudentDTO dto) {
        Student student = getStudentById(id);

        student.setSurname(dto.getSurname());
        student.setName(dto.getName());
        student.setPatronymic(dto.getPatronymic());
        student.setGroupNumber(dto.getGroupNumber());
        student.setFaculty(dto.getFaculty());
        student.setPhoneNumber(dto.getPhoneNumber());
        student.setTelegramUsername(dto.getTelegramUsername());
        student.setEmail(dto.getEmail());
        student.setDormitoryResidence(dto.isDormitoryResidence());
        student.setDormBlockNumber(dto.getDormBlockNumber());
        student.setDormNumber(dto.getDormNumber());
        student.setFullNameDative(dto.getFullNameDative());
        student.setBrsmMember(dto.isBrsmMember());

        if (dto.getPhoto() != null && dto.getPhoto().length > 0) {
            student.setPhoto(dto.getPhoto());
        }

        return studentRepository.save(student);
    }

    @Override
    public List<Student> findAllOnlyStudents() {
        return studentRepository.findAllWithStudentRole();
    }

    @Override
    public List<User> findAllOnlySecretaries() {
        return userRepository.findAllByRolesWithStudent(
                List.of(RoleEnum.SECRETARY, RoleEnum.CHIEF_SECRETARY));
    }

    @Override
    public List<FacultyStatisticsDTO> getStudentCountByFaculty() {
        return studentRepository.countStudentsByFaculty()
                .stream()
                .map(row -> new FacultyStatisticsDTO((Faculty) row[0], (Long) row[1]))
                .toList();
    }

    @Override
    @Transactional
    public Student createStudentWithUser(CreateStudentRequestDTO request) {
        if (userRepository.findByLogin(request.getLogin()).isPresent()) {
            throw new EntityExistsException("Пользователь с таким логином уже существует");
        }

        if (studentRepository.existsBySurnameAndNameAndPatronymicAndGroupNumber(
                request.getSurname(), request.getName(),
                request.getPatronymic(), request.getGroupNumber())) {
            throw new EntityExistsException("Студент с такими ФИО и группой уже существует");
        }

        Student student = studentMapper.toEntity(request);
        Student savedStudent = studentRepository.save(student);

        User user = User.builder()
                .login(request.getLogin())
                .password(passwordEncoder.encode(request.getLogin()))
                .role(RoleEnum.STUDENT)
                .student(savedStudent)
                .build();
        userRepository.save(user);

        return savedStudent;
    }
}

package org.brsm_system_server.service;

import org.brsm_system_server.entity.Secretary;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.entity.User;
import org.brsm_system_server.entity.enums.RoleEnum;
import org.brsm_system_server.repository.*;
import org.brsm_system_server.service.interfaces.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class UserService implements IUserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private StudentRepository studentRepository;

    @Autowired
    private SecretaryRepository secretaryRepository;

    @Autowired
    private StudentEventRepository studentEventRepository;

    @Autowired
    private ExemptionStudentsRepository exemptionStudentsRepository;

    @Autowired
    private StudentReportRepository studentReportRepository;

    @Override
    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    @Override
    public Student findStudentById(Long id) {
        User userP = userRepository.findById(id).orElse(null);
        if (userP != null) {
            Student student = userP.getStudent();
            return student;
        }
        return null;
    }

    @Override
    public Secretary findSecretaryById(Long id) {
        User userP = userRepository.findById(id).orElse(null);
        if (userP != null) {
            Secretary secretary = userP.getSecretary();
            return secretary;
        }
        return null;
    }

    @Override
    @Transactional
    public void changeUserRole(Long userId, RoleEnum newRole) {
        User user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (newRole == RoleEnum.SECRETARY && user.getStudent() != null) {
            Student student = user.getStudent();

            studentEventRepository.deleteAllStudentEvents(student.getStudentId());
            exemptionStudentsRepository.deleteAllExemptionStudents(student.getStudentId());
            studentReportRepository.deleteAllStudentReports(student.getStudentId());
            studentRepository.delete(student);
            user.setStudent(null);

            Secretary secretary = new Secretary();
            secretary.setLastName(student.getLastName());
            secretary.setFirstName(student.getFirstName());
            secretary.setMiddleName(student.getMiddleName());
            secretary.setSecretaryFaculty(student.getStudentFaculty());
            secretary.setImage(student.getImage());
            secretary.setTelegramUsername(student.getTelegram());
            secretaryRepository.save(secretary);

            user.setSecretary(secretary);
        } else if (newRole == RoleEnum.STUDENT && user.getSecretary() != null) {
            Secretary secretary = user.getSecretary();

            Student student = new Student();
            student.setLastName(secretary.getLastName());
            student.setFirstName(secretary.getFirstName());
            student.setMiddleName(secretary.getMiddleName());
            student.setStudentFaculty(secretary.getSecretaryFaculty());
            student.setImage(secretary.getImage());
            student.setTelegram(secretary.getTelegramUsername());
            studentRepository.save(student);

            secretaryRepository.delete(secretary);
            user.setSecretary(null);
            user.setStudent(student);
        }

        user.setRole(newRole);
        userRepository.save(user);
    }
}

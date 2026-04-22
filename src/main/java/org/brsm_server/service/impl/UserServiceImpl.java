package org.brsm_server.service.impl;

import org.brsm_server.entity.Student;
import org.brsm_server.entity.User;
import org.brsm_server.repository.*;
import org.brsm_server.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private StudentRepository studentRepository;

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

    //TODO: переписать на новую реализацию с общей сущностью для студентов и секретарей
//    @Override
//    @Transactional
//    public void changeUserRole(Long userId, RoleEnum newRole) {
//        User user = userRepository.findById(userId).orElseThrow(() -> new IllegalArgumentException("User not found"));
//
//        if (newRole == RoleEnum.SECRETARY && user.getStudent() != null) {
//            Student student = user.getStudent();
//
//            studentEventRepository.deleteAllStudentEvents(student.getStudentId());
//            exemptionStudentsRepository.deleteAllExemptionStudents(student.getStudentId());
//            studentReportRepository.deleteAllStudentReports(student.getStudentId());
//            studentRepository.delete(student);
//            user.setStudent(null);
//
//            Secretary secretary = new Secretary();
//            secretary.setLastName(student.getLastName());
//            secretary.setFirstName(student.getFirstName());
//            secretary.setMiddleName(student.getMiddleName());
//            secretary.setSecretaryFaculty(student.getStudentFaculty());
//            secretary.setImage(student.getImage());
//            secretary.setTelegramUsername(student.getTelegram());
//            secretaryRepository.save(secretary);
//
//            user.setSecretary(secretary);
//        } else if (newRole == RoleEnum.STUDENT && user.getSecretary() != null) {
//            Secretary secretary = user.getSecretary();
//
//            Student student = new Student();
//            student.setLastName(secretary.getLastName());
//            student.setFirstName(secretary.getFirstName());
//            student.setMiddleName(secretary.getMiddleName());
//            student.setStudentFaculty(secretary.getSecretaryFaculty());
//            student.setImage(secretary.getImage());
//            student.setTelegram(secretary.getTelegramUsername());
//            studentRepository.save(student);
//
//            secretaryRepository.delete(secretary);
//            user.setSecretary(null);
//            user.setStudent(student);
//        }
//
//        user.setRole(newRole);
//        userRepository.save(user);
//    }
}

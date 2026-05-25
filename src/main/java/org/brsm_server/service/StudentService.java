package org.brsm_server.service;

import org.brsm_server.dto.CreateStudentRequestDTO;
import org.brsm_server.dto.FacultyStatisticsDTO;
import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.Student;
import org.brsm_server.entity.User;

import java.util.List;

public interface StudentService {

    List<Student> findAllStudentsAndSecretaries();

    Student getStudentById(Long id);

    List<Student> getStudentsByEventId(Long eventId);

    List<Student> findEligibleStudents();

    Student updateStudent(Long id, StudentDTO dto);

    /**
     * Получить всех с ролью СТУДЕНТ
     * @return список пользователей с ролью студент
     */
    List<Student> findAllOnlyStudents();

    List<User> findAllOnlySecretaries();

    List<FacultyStatisticsDTO> getStudentCountByFaculty();

    /**
     * Создание студента секретарём: сохраняет Student и связанного User с ролью STUDENT
     */
    Student createStudentWithUser(CreateStudentRequestDTO request);
}

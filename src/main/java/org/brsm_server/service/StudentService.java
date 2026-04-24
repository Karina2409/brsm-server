package org.brsm_server.service;

import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.Student;

import java.util.List;

public interface StudentService {

    List<Student> findAllStudents();

    Student getStudentById(Long id);

    List<Student> getStudentsByEventId(Long eventId);

    List<Student> findEligibleStudents();

    Student createStudent(Student student);

    Student updateStudent(Long id, StudentDTO dto);

}

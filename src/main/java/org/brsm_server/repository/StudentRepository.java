package org.brsm_server.repository;

import org.brsm_server.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Date;
import java.util.List;

public interface StudentRepository extends JpaRepository<Student, Long> {

    @Query("SELECT s FROM Student s JOIN s.events e WHERE e.eventId = :eventId")
    List<Student> findStudentsByEventId(@Param("eventId") Long eventId);

    @Query("SELECT DISTINCT s FROM Student s JOIN s.events e WHERE e.date >= :startDate")
    List<Student> findStudentsByEventDateAfter(@Param("startDate") Date startDate);

    @Query("SELECT SUM(e.optCount) FROM Student s JOIN s.events e WHERE s.studentId = :studentId AND e.date BETWEEN :startDate AND CURRENT_DATE ")
    Integer findOptCountByStudentIdAndEventDateAfter(@Param("studentId") Long studentId, @Param("startDate") Date startDate);

    @Query("SELECT s.faculty, COUNT(s) " +
            "FROM Student s JOIN s.events e " +
            "WHERE e.date BETWEEN :startDate AND :endDate " +
            "GROUP BY s.faculty")
    List<Object[]> countStudentsByFacultyBetweenDates(@Param("startDate") Date startDate, @Param("endDate") Date endDate);

    boolean existsBySurnameAndNameAndPatronymicAndGroupNumber(
            String surname, String name, String patronymic, String groupNumber);

    @Query("SELECT u.student FROM User u WHERE u.role = org.brsm_server.entity.enums.RoleEnum.STUDENT AND u.student IS NOT NULL")
    List<Student> findAllWithStudentRole();

}

package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Date;
import java.util.List;

public interface StudentRepository extends JpaRepository<Student, Long> {

    @Query("SELECT s FROM Student s JOIN s.events e WHERE e.eventId = :eventId")
    List<Student> findStudentsByEventId(@Param("eventId") Long eventId);

    @Query("SELECT DISTINCT s FROM Student s JOIN s.events e WHERE e.eventDate >= :startDate")
    List<Student> findStudentsByEventDateAfter(@Param("startDate") Date startDate);

    @Query("SELECT SUM(e.optCount) FROM Student s JOIN s.events e WHERE s.studentId = :studentId AND e.eventDate BETWEEN :startDate AND CURRENT_DATE ")
    Integer findOptCountByStudentIdAndEventDateAfter(@Param("studentId") Long studentId, @Param("startDate") Date startDate);

    @Query("SELECT s.studentFaculty, COUNT(s) " +
            "FROM Student s JOIN s.events e " +
            "WHERE e.eventDate BETWEEN :startDate AND :endDate " +
            "GROUP BY s.studentFaculty")
    List<Object[]> countStudentsByFacultyBetweenDates(@Param("startDate") Date startDate, @Param("endDate") Date endDate);

    boolean existsByLastNameAndFirstNameAndMiddleNameAndGroupNumber(
            String lastName, String firstName, String middleName, String groupNumber);}

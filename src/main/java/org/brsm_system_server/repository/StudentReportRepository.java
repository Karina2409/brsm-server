package org.brsm_system_server.repository;

import jakarta.transaction.Transactional;
import org.brsm_system_server.entity.Report;
import org.brsm_system_server.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Set;

public interface StudentReportRepository extends JpaRepository<Report, Long> {

    @Modifying
    @Transactional
    @Query(value = "INSERT INTO student_report (student_id, report_id, opt) VALUES (:studentId, :reportId, :optCount)", nativeQuery = true)
    void addStudentToReport(@Param("studentId") Long studentId, @Param("reportId") Long reportId, @Param("optCount") Integer optCount);

    @Query("SELECT s FROM Student s JOIN s.reports r WHERE r.reportId = :reportId")
    Set<Student> findStudentsByReportId(@Param("reportId") Long reportId);

    @Query(value = "SELECT opt FROM student_report WHERE student_id = :studentId AND report_id = :reportId", nativeQuery = true)
    Integer findOptByStudentId(@Param("studentId") Long studentId, @Param("reportId") Long reportId);

    @Modifying
    @Transactional
    @Query(value = "DELETE FROM student_report WHERE student_id = :studentId AND report_id = :reportId", nativeQuery = true)
    void removeStudentFromReport(@Param("studentId") Long studentId, @Param("reportId") Long reportId);

    @Modifying
    @Transactional
    @Query(value = "DELETE FROM student_report WHERE student_id = :studentId", nativeQuery = true)
    void deleteAllStudentReports(@Param("studentId") Long studentId);

}

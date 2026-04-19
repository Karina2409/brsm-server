package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Exemption;
import org.brsm_system_server.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

public interface ExemptionStudentsRepository extends JpaRepository<Exemption, Long> {

    @Modifying
    @Query(value = "INSERT INTO exemption_students (exemption_id, student_id) VALUES (:exemptionId, :studentId)", nativeQuery = true)
    void saveExemptionStudent(@Param("exemptionId") Long exemptionId, @Param("studentId") Long studentId);

    @Query("SELECT e.students FROM Exemption e WHERE e.exemptionId = :exemptionId")
    Set<Student> findStudentsByExemptionId(@Param("exemptionId") Long exemptionId);

    @Modifying
    @Transactional
    @Query(value = "DELETE FROM exemption_students WHERE student_id = :studentId", nativeQuery = true)
    void deleteAllExemptionStudents(@Param("studentId") Long studentId);
}

package org.brsm_server.repository;

import org.brsm_server.entity.Petition;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface PetitionRepository extends JpaRepository<Petition, Long> {

    @Query("SELECT p FROM Petition p WHERE p.deleted = false")
    List<Petition> findAllActive();

    @Query("SELECT CASE WHEN COUNT(p) > 0 THEN FALSE ELSE TRUE END FROM Petition p WHERE p.student.studentId = :studentId AND p.deleted = false")
    boolean existsStudentInPetitions(@Param("studentId") Long studentId);

    @Modifying
    @Query("DELETE FROM Petition p WHERE p.student.studentId = :studentId AND p.deleted = true")
    void deleteByStudentIdAndDeletedTrue(@Param("studentId") Long studentId);

}

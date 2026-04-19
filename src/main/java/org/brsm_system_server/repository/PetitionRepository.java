package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Petition;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PetitionRepository extends JpaRepository<Petition, Long> {

    @Query("SELECT CASE WHEN COUNT(p) > 0 THEN FALSE ELSE TRUE END FROM Petition p WHERE p.student.studentId = :studentId")
    boolean existsStudentInPetitions(@Param("studentId") Long studentId);

}

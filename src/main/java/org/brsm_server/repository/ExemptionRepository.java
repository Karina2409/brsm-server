package org.brsm_server.repository;

import org.brsm_server.entity.Exemption;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ExemptionRepository extends JpaRepository<Exemption, Long> {

    @Query("SELECT e FROM Exemption e WHERE e.deleted = false")
    List<Exemption> findAllActive();
}

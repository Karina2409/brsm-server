package org.brsm_server.repository;

import org.brsm_server.entity.Exemption;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ExemptionRepository extends JpaRepository<Exemption, Long> {
}

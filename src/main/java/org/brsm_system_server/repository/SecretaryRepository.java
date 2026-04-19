package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Secretary;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecretaryRepository extends JpaRepository<Secretary, Long> {
}

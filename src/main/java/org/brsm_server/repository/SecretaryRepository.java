package org.brsm_server.repository;

import org.brsm_server.entity.Secretary;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecretaryRepository extends JpaRepository<Secretary, Long> {
}

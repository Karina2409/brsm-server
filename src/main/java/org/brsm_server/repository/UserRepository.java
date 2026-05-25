package org.brsm_server.repository;

import org.brsm_server.entity.User;
import org.brsm_server.entity.enums.Faculty;
import org.brsm_server.entity.enums.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByLogin(String login);

    @Query("SELECT u FROM User u WHERE u.role IN :roles AND u.student IS NOT NULL AND u.deleted = false")
    List<User> findAllByRolesWithStudent(@Param("roles") List<RoleEnum> roles);

    @Query("SELECT u FROM User u WHERE u.role = :role AND u.student.faculty = :faculty AND u.deleted = false")
    Optional<User> findActiveSecretaryByFaculty(@Param("role") RoleEnum role, @Param("faculty") Faculty faculty);
}

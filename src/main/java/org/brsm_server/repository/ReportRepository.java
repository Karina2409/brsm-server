package org.brsm_server.repository;

import org.brsm_server.entity.Report;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.OffsetDateTime;
import java.util.List;

public interface ReportRepository extends JpaRepository<Report, Long> {

    @Query("SELECT r FROM Report r WHERE r.deleted = false")
    List<Report> findAllActive();

    @Query("SELECT r FROM Report r WHERE r.createdAt >= :startDate AND r.deleted = false")
    List<Report> findReportsByDateAfter(@Param("startDate") OffsetDateTime startDate);
}

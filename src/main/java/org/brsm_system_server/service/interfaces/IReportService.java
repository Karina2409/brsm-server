package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Report;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Set;

public interface IReportService {
    List<Report> getAllReports();
    ResponseEntity<Set<Report>> saveReport();
    ResponseEntity<Void> deleteReportById(Long id);
    void downloadReport(Long reportId);
}

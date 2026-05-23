package org.brsm_server.service;

import org.brsm_server.entity.Report;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Set;

public interface ReportService {
    List<Report> getAllReports();
    Set<Report> saveReport();
    ResponseEntity<Void> deleteReportById(Long id);
    byte[] downloadReport(Long reportId);
}

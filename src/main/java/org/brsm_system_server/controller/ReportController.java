package org.brsm_system_server.controller;

import org.brsm_system_server.dto.ReportDTO;
import org.brsm_system_server.entity.Report;
import org.brsm_system_server.mapper.ReportMapper;
import org.brsm_system_server.service.interfaces.IReportService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/reports")
public class ReportController {

    @Autowired
    private IReportService reportService;

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/get-all")
    public List<ReportDTO> getReports(){
        List<Report> reports = reportService.getAllReports();
        return reports.stream().map(ReportMapper::toDto).toList();
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PostMapping("/post/month")
    public ResponseEntity<Set<Report>> createReport(){
        return reportService.saveReport();
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @DeleteMapping("/delete/{reportId}")
    public ResponseEntity<Void> deleteReport(@PathVariable Long reportId){
        return reportService.deleteReportById(reportId);
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PostMapping("/download/{reportId}")
    public void downloadReport(@PathVariable Long reportId){
        reportService.downloadReport(reportId);
    }
}

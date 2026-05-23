package org.brsm_server.controller;

import lombok.RequiredArgsConstructor;
import org.brsm_server.dto.ReportDTO;
import org.brsm_server.entity.Report;
import org.brsm_server.mapper.ReportMapper;
import org.brsm_server.security.Roles;
import org.brsm_server.service.ReportService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/reports")
@RequiredArgsConstructor
public class ReportController {

    private final ReportService reportService;
    private final ReportMapper reportMapper;

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping
    public List<ReportDTO> getReports(){
        List<Report> reports = reportService.getAllReports();
        return reports.stream().map(reportMapper::toDto).toList();
    }

    @PreAuthorize(Roles.SECRETARIES)
    @PostMapping
    public ResponseEntity<Set<ReportDTO>> createReport(){
        Set<Report> reports = reportService.saveReport();
        return ResponseEntity.ok(
                reports
                        .stream()
                        .map(reportMapper::toDto)
                        .collect(Collectors.toSet())
        );
    }

    @PreAuthorize(Roles.SECRETARIES)
    @DeleteMapping("/{reportId}")
    public ResponseEntity<Void> deleteReport(@PathVariable Long reportId){
        return reportService.deleteReportById(reportId);
    }

    @PreAuthorize(Roles.SECRETARIES)
    @PostMapping("/{reportId}")
    public ResponseEntity<byte[]> downloadReport(@PathVariable Long reportId){
        byte[] pdfContents = reportService.downloadReport(reportId);

        if (pdfContents == null || pdfContents.length == 0) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"report_" + reportId + ".pdf\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdfContents);
    }
}

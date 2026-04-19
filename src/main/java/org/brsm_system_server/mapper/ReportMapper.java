package org.brsm_system_server.mapper;

import org.brsm_system_server.dto.ReportDTO;
import org.brsm_system_server.entity.Report;

public class ReportMapper {
    public static ReportDTO toDto(Report report) {
        return new ReportDTO(
                report.getReportId(),
                report.getReportName(),
                report.getDormNumber(),
                report.getReportDate()
        );
    }
}

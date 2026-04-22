package org.brsm_server.mapper;

import org.brsm_server.dto.ReportDTO;
import org.brsm_server.entity.Report;

import java.util.Date;

public class ReportMapper {
    public static ReportDTO toDto(Report report) {
        return new ReportDTO(
                report.getReportId(),
                report.getName(),
                report.getDormNumber(),
                Date.from(report.getCreatedAt().toInstant())
        );
    }
}

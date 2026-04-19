package org.brsm_system_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Date;

@Data
@AllArgsConstructor
public class ReportDTO {
    private Long reportId;
    private String reportName;
    private int dormNumber;
    private Date reportDate;

}

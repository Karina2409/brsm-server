package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.Date;

@Data
@AllArgsConstructor
public class ReportDTO {
    private Long reportId;
    private String name;
    private int dormNumber;
    private Date reportDate;

}

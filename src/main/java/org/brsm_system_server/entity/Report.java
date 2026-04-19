package org.brsm_system_server.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.Data;

import java.util.Date;
import java.util.List;
import java.util.Set;

@Data
@Entity
@Table(name="report")
public class Report {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "report_id")
    private Long reportId;

    @Column(name = "report_name")
    private String reportName;

    @Column(name = "dorm_number")
    private int dormNumber;

    @Column(columnDefinition = "DATE", name = "report_date")
    @JsonFormat(pattern = "yyyy-MM-dd", timezone = "Europe/Minsk")
    private Date reportDate;

    @ManyToMany(mappedBy = "reports")
    private Set<Student> students;
}

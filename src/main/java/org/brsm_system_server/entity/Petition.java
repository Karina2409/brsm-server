package org.brsm_system_server.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.Data;
import org.brsm_system_server.entity.enums.FacultyEnum;

import java.util.Date;

@Data
@Entity
@Table(name="petition")
public class Petition {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "petition_id")
    private Long petitionId;

    @Column(name = "petition_name")
    private String petitionName;

    @Column(columnDefinition = "DATE", name = "petition_date")
    @JsonFormat(pattern = "yyyy-MM-dd", timezone = "Europe/Minsk")
    private Date petitionDate;

    @Column(name = "student_faculty")
    @Enumerated(EnumType.STRING)
    private FacultyEnum studentFacultyPetition;

    @Column(name="student_name")
    private String studentLastName;

    @OneToOne
    @JoinColumn(name = "student_id")
    private Student student;
}

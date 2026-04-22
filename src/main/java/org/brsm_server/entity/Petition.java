package org.brsm_server.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.Data;
import org.brsm_server.entity.enums.Faculty;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;
import java.util.Date;

@Data
@Entity
@Table(name="petition")
public class Petition {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "petition_id")
    private Long petitionId;

    private String name;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "student_faculty")
    private Faculty studentFaculty;

    @Column(name="student_last_name")
    private String studentLastName;

    @OneToOne
    @JoinColumn(name = "student_id")
    private Student student;

    @ColumnDefault("false")
    private boolean deleted;
}

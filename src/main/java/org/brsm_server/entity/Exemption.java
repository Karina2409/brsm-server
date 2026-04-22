package org.brsm_server.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.Data;
import org.brsm_server.entity.enums.Faculty;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;
import java.util.Date;
import java.util.Set;

@Data
@Entity
@Table(name="exemption")
public class Exemption {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "exemption_id")
    private Long exemptionId;

    private String name;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "students_faculty")
    private Faculty studentsFaculty;

    @Column(name="event_name")
    private String eventName;

    @ManyToOne
    @JoinColumn(name = "event_id")
    private Event event;

    @ManyToMany
    @JoinTable(
            name = "exemption_students",
            joinColumns = @JoinColumn(name = "exemption_id"),
            inverseJoinColumns = @JoinColumn(name = "student_id")
    )
    private Set<Student> students;

    @ColumnDefault("false")
    private boolean deleted;
}


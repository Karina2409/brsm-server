package org.brsm_server.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Time;
import java.time.OffsetDateTime;

@Data
@Entity
@Table(name = "event_templates")
@AllArgsConstructor
@NoArgsConstructor
public class EventTemplate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "template_id")
    private Long templateId;

    @Column(name = "template_name")
    private String templateName;

    @Column(name = "default_time", columnDefinition = "TIME")
    private Time defaultTime;

    @Column(name = "default_place")
    private String defaultPlace;

    @Column(name = "default_student_count")
    private int defaultStudentCount;

    @Column(name = "default_for_petition")
    private int defaultForPetition;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    @ColumnDefault("false")
    private boolean deleted;
}

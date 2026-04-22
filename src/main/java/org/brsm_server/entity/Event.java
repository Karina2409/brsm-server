package org.brsm_server.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.CreationTimestamp;

import java.sql.Time;
import java.time.OffsetDateTime;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Data
@Entity
@Table(name = "events")
@AllArgsConstructor
@NoArgsConstructor
public class Event {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "event_id")
    private Long eventId;

    @ManyToMany(mappedBy = "events")
    private Set<Student> students;

    private String name;

    @Column(columnDefinition = "DATE")
    @JsonFormat(pattern = "yyyy-MM-dd", timezone = "Europe/Minsk")
    private Date date;

    @Column(columnDefinition = "TIME")
    @JsonFormat(pattern = "HH:mm:ss", timezone = "Europe/Minsk")
    private Time time;

    private String place;

    @Column(name = "student_count")
    private int studentCount;

    @Column(name = "opt_count")
    private int optCount;

    @Column(name = "for_petition")
    private boolean forPetition;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;

    @ManyToOne
    @JoinColumn(name = "template_id")
    private EventTemplate templateUsed;

    @ColumnDefault("false")
    private boolean deleted;

    @OneToMany(mappedBy = "event")
    private Set<Exemption> exceptions = new HashSet<>();

}

package org.brsm_system_server.entity;


import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.sql.Time;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@AllArgsConstructor
@Data
@Entity
@Table(name = "events")
public class Event {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "event_id")
    private Long eventId;

    @ManyToMany(mappedBy = "events")
    private Set<Student> students;

    @Column(name = "event_name")
    private String eventName;

    @Column(name = "event_date", columnDefinition = "DATE")
    @JsonFormat(pattern = "yyyy-MM-dd", timezone = "Europe/Minsk")
    private Date eventDate;

    @Column(name = "event_time", columnDefinition = "TIME")
    @JsonFormat(pattern = "HH:mm:ss", timezone = "Europe/Minsk")
    private Time eventTime;

    @Column(name = "event_place")
    private String eventPlace;

    @Column(name = "student_count")
    private int studentCount;

    @Column(name = "opt_count")
    private int optCount;

    @Column(name = "for_petition")
    private boolean forPetition;

    @OneToMany(mappedBy = "event")
    private Set<Exemption> exceptions = new HashSet<>();

    public Event() {}

}

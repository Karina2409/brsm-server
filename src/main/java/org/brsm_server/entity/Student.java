package org.brsm_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.brsm_server.entity.enums.Faculty;
import org.hibernate.annotations.ColumnDefault;

import java.time.LocalDate;
import java.util.Set;

@Data
@Entity
@Table(name = "students")
public class Student {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "student_id")
    private Long studentId;

    @ManyToMany
    @JoinTable(
            name = "students_has_events",
            joinColumns = @JoinColumn(name = "students_student_id"),
            inverseJoinColumns = @JoinColumn(name = "events_event_id")
    )
    private Set<Event> events;

    @ManyToMany(mappedBy = "students")
    private Set<Exemption> exception;

    @Column(name="full_name_dative")
    private String fullNameDative;

    @Column(name = "last_name")
    private String lastName;

    @Column(name="first_name")
    private String firstName;

    private String patronymic;

    @Column (name = "group_number")
    private String groupNumber;

    @Enumerated(EnumType.STRING)
    @Column(name = "faculty")
    private Faculty faculty;

    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    private String email;

    @Column(name = "telegram_username")
    private String telegramUsername;

    @Column(name = "dormitory_residence")
    private boolean dormitoryResidence;

    @Column(name = "dorm_block_number")
    private String dormBlockNumber;

    @Column(name = "dorm_number")
    private Integer dormNumber;

    @Lob
    @Column(name = "photo")
    private byte[] photo;

    @ColumnDefault("false")
    @Column(name = "is_brsm_member")
    private boolean isBrsmMember;

    @Column(name = "phone_number")
    private String phoneNumber;

    @ManyToMany
    @JoinTable(
            name = "student_report",
            joinColumns = @JoinColumn(name = "student_id"),
            inverseJoinColumns = @JoinColumn(name = "report_id")
    )
    private Set<Report> reports;

}

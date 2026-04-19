package org.brsm_system_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.brsm_system_server.entity.enums.FacultyEnum;

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

    @Column(name="student_full_name_d")
    private String studentFullNameD;

    @Column(name = "last_name")
    private String lastName;

    @Column(name="first_name")
    private String firstName;

    @Column(name = "middle_name")
    private String middleName;

    @Column (name = "group_number")
    private String groupNumber;

    @Enumerated(EnumType.STRING)
    @Column(name = "student_faculty")
    private FacultyEnum studentFaculty;

    @Column(name = "dormitory_residence")
    private boolean dormitoryResidence;

    @Column(name = "dorm_block_number")
    private String dormBlockNumber;

    @Column(name = "dorm_number")
    private Integer dormNumber;

    @Lob
    @Column(name = "image", columnDefinition = "LONGBLOB")
    private byte[] image;

    @Column(name = "is_brsm_member")
    private boolean isBrsmMember;

    @Column(name = "student_telegram")
    private String telegram;

    @Column(name = "student_phone_number")
    private String phoneNumber;

    @ManyToMany
    @JoinTable(
            name = "student_report",
            joinColumns = @JoinColumn(name = "student_id"),
            inverseJoinColumns = @JoinColumn(name = "report_id")
    )
    private Set<Report> reports;

}

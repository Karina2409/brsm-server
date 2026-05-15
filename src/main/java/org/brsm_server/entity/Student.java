package org.brsm_server.entity;

import jakarta.persistence.*;
import lombok.*;
import org.brsm_server.entity.enums.Faculty;
import org.hibernate.annotations.ColumnDefault;

import java.time.LocalDate;
import java.util.Set;

@Getter
@Setter
@Entity
@Table(name = "students")
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = "events")
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

    private String surname;

    private String name;

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

    @Transient
    public String getShortFio() {
        if (surname == null) return null;

        String n = (name != null && !name.isEmpty()) ? name.charAt(0) + "." : "";
        String p = (patronymic != null && !patronymic.isEmpty()) ? patronymic.charAt(0) + "." : "";

        return surname + " " + n + p;
    }
}

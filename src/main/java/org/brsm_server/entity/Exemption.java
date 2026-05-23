package org.brsm_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.brsm_server.entity.enums.Faculty;
import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = true)
@Entity
@DiscriminatorValue("EXEMPTION")
public class Exemption extends Document {

    @Enumerated(EnumType.STRING)
    @Column(name = "student_faculty")
    private Faculty studentFaculty;

    @Column(name="event_name")
    private String eventName;

    @ManyToOne
    @JoinColumn(name = "event_id")
    private Event event;

    @ManyToMany
    @JoinTable(
            name = "exemption_students",
            joinColumns = @JoinColumn(name = "document_id"),
            inverseJoinColumns = @JoinColumn(name = "student_id")
    )
    private Set<Student> students;
}


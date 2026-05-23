package org.brsm_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.brsm_server.entity.enums.Faculty;

@Data
@EqualsAndHashCode(callSuper = true)
@Entity
@DiscriminatorValue("PETITION")
public class Petition extends Document {

    @Enumerated(EnumType.STRING)
    @Column(name = "student_faculty")
    private Faculty studentFaculty;

    @Column(name="student_last_name")
    private String studentLastName;

    @OneToOne
    @JoinColumn(name = "student_id")
    private Student student;
}

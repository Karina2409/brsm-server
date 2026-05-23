package org.brsm_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Set;

@Data
@EqualsAndHashCode(callSuper = true)
@Entity
@DiscriminatorValue("REPORT")
public class Report extends Document {

    @Column(name = "dorm_number")
    private Integer dormNumber;

    @ManyToMany
    @JoinTable(
            name = "report_students",
            joinColumns = @JoinColumn(name = "document_id"),
            inverseJoinColumns = @JoinColumn(name = "student_id")
    )
    private Set<Student> students;
}

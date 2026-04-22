package org.brsm_server.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.brsm_server.entity.enums.Faculty;

@Data
@Entity
@Table(name = "deans")
@AllArgsConstructor
@NoArgsConstructor
public class Dean {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "dean_id")
    private Long deanId;

    @Enumerated(EnumType.STRING)
    @Column(name = "faculty")
    private Faculty faculty;

    @Column(name = "dean_name")
    private String deanName;
}

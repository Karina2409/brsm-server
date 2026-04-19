package org.brsm_system_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.brsm_system_server.entity.enums.FacultyEnum;

@Data
@Entity
@Table(name = "secretaries")
public class Secretary {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "secretary_id")
    private Long secretaryId;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "middle_name")
    private String middleName;

    @Enumerated(EnumType.STRING)
    @Column(name = "secretary_faculty")
    private FacultyEnum secretaryFaculty;

    @Column(name = "telegram_username")
    private String telegramUsername;

    @Lob
    @Column(name = "image", columnDefinition = "LONGBLOB")
    private byte[] image;

}

package org.brsm_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.hibernate.annotations.ColumnDefault;

@Data
@Entity
@Table(name = "settings")
public class Setting {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "setting_id")
    private Long settingId;

    private String name;

    private String value;

    private String description;

    @Column(name = "created_by")
    private Long createdBy;

    @ColumnDefault("false")
    private boolean deleted;
}

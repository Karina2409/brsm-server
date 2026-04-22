package org.brsm_server.entity;

import jakarta.persistence.*;
import lombok.Data;
import org.brsm_server.entity.enums.ActionType;
import org.brsm_server.entity.enums.RoleEnum;
import org.hibernate.annotations.CreationTimestamp;

import java.time.OffsetDateTime;

@Data
@Entity
@Table(name = "users_actions")
public class UserAction {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "action_id")
    private Long actionId;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    private RoleEnum role;

    @Column(name = "action_area")
    private String actionArea;

    @Column(name = "action_type")
    private ActionType actionType;

    @Column(name = "action_description")
    private String actionDescription;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private OffsetDateTime createdAt;
}

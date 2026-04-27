package org.brsm_server.security.token;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Data;

import java.util.Date;

@Entity
@Data
public class BlacklistedToken {

    @Id
    @GeneratedValue
    private Long id;

    @Column(unique = true)
    private String token;

    private Date expiryDate;
}

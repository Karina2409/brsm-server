package org.brsm_server.auth;

import lombok.Data;

@Data
public class RefreshRequest {
    private String refreshToken;
}

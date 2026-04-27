package org.brsm_server.security.token;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final BlacklistedTokenRepository repository;

    public void blacklist(String token, Date expiry) {
        BlacklistedToken t = new BlacklistedToken();
        t.setToken(token);
        t.setExpiryDate(expiry);
        repository.save(t);
    }

    public boolean isBlacklisted(String token) {
        return repository.existsByToken(token);
    }
}

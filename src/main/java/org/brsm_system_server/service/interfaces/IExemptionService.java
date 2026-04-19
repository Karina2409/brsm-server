package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Exemption;
import org.springframework.http.ResponseEntity;

import java.util.List;
import java.util.Set;

public interface IExemptionService {
    List<Exemption> getAllExemptions();
    void saveExemption(Long eventId, Set<Long> studentIds);
    ResponseEntity<Void> deleteExemptionById(Long exemptionId);
    ResponseEntity<Void> downloadExemption(Long exemptionId);
}

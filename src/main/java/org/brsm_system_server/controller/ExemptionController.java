package org.brsm_system_server.controller;

import org.brsm_system_server.dto.ExemptionDTO;
import org.brsm_system_server.entity.Exemption;
import org.brsm_system_server.mapper.ExemptionMapper;
import org.brsm_system_server.service.interfaces.IExemptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/exemptions")
public class ExemptionController {

    @Autowired
    private IExemptionService exemptionService;

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/get-all")
    public List<ExemptionDTO> getExemptions() {
        List<Exemption> exemptions = exemptionService.getAllExemptions();
        return exemptions.stream().map(ExemptionMapper::toDto).toList();
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PostMapping("/post/{eventId}")
    public ResponseEntity<Void> createExemption(@PathVariable("eventId") Long eventId,
                                                @RequestBody Map<String, Set<Long>> request) throws MissingServletRequestParameterException {
        Set<Long> studentIds = request.get("studentIds");
        if (studentIds == null || studentIds.isEmpty()) {
            throw new MissingServletRequestParameterException("studentIds", "Set<Long>");
        }
        exemptionService.saveExemption(eventId, studentIds);
        return ResponseEntity.ok().build();
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @DeleteMapping("/delete/{exemptionId}")
    public ResponseEntity<Void> deleteExemption(@PathVariable Long exemptionId) {
        return exemptionService.deleteExemptionById(exemptionId);
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PostMapping("/download/{exemptionId}")
    public ResponseEntity<Void> downloadExemption(@PathVariable Long exemptionId) {
        return exemptionService.downloadExemption(exemptionId);
    }
}

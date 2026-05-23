package org.brsm_server.controller;

import lombok.RequiredArgsConstructor;
import org.brsm_server.dto.ExemptionDTO;
import org.brsm_server.entity.Exemption;
import org.brsm_server.mapper.ExemptionMapper;
import org.brsm_server.security.Roles;
import org.brsm_server.service.ExemptionService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/exemptions")
@RequiredArgsConstructor
public class ExemptionController {

    private final ExemptionService exemptionService;
    private final ExemptionMapper exemptionMapper;

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping
    public List<ExemptionDTO> getExemptions() {
        List<Exemption> exemptions = exemptionService.getAllExemptions();
        return exemptions.stream().map(exemptionMapper::toDto).toList();
    }

    @PreAuthorize(Roles.SECRETARIES)
    @PostMapping("/{eventId}")
    public ResponseEntity<Void> createExemption(@PathVariable("eventId") Long eventId,
                                                @RequestBody Map<String, Set<Long>> request) throws MissingServletRequestParameterException {
        Set<Long> studentIds = request.get("studentIds");
        if (studentIds == null || studentIds.isEmpty()) {
            throw new MissingServletRequestParameterException("studentIds", "Set<Long>");
        }
        exemptionService.saveExemption(eventId, studentIds);
        return ResponseEntity.ok().build();
    }

    @PreAuthorize(Roles.SECRETARIES)
    @DeleteMapping("/{exemptionId}")
    public ResponseEntity<Void> deleteExemption(@PathVariable Long exemptionId) {
        return exemptionService.deleteExemptionById(exemptionId);
    }

    @PreAuthorize(Roles.SECRETARIES)
    @PostMapping("/download/{exemptionId}")
    public ResponseEntity<byte[]> downloadExemption(@PathVariable Long exemptionId) {
        byte[] pdfContents = exemptionService.downloadExemption(exemptionId);

        if (pdfContents == null || pdfContents.length == 0) {
            return ResponseEntity.noContent().build();
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"exemption_" + exemptionId + ".pdf\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdfContents);
    }
}

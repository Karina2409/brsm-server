package org.brsm_server.controller;

import lombok.RequiredArgsConstructor;
import org.brsm_server.security.Roles;
import org.brsm_server.service.StudentEventService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/se")
@RequiredArgsConstructor
public class StudentEventController {
    private final StudentEventService studentEventService;

    @PreAuthorize(Roles.STUDENT)
    @PostMapping("/{studentId}/events/{eventId}")
    public void addEventToStudent(@PathVariable Long studentId, @PathVariable Long eventId) {
        studentEventService.addEventToStudent(studentId, eventId);
    }

    @PreAuthorize(Roles.STUDENT)
    @DeleteMapping("/remove/student/{studentId}/event/{eventId}")
    public void removeEventFromStudent(@PathVariable("studentId") Long studentId, @PathVariable("eventId") Long eventId) {
        studentEventService.removeEventFromStudent(studentId, eventId);
    }

    @PreAuthorize(Roles.STUDENT)
    @GetMapping("/student/{studentId}/ids")
    public List<Long> getRegisteredEventIds(@PathVariable Long studentId) {
        return studentEventService.getRegisteredEventIds(studentId);
    }
}

package org.brsm_system_server.controller;

import org.brsm_system_server.service.interfaces.IStudentEventService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/se")
public class StudentEventController {

    @Autowired
    private IStudentEventService studentEventService;

    @PreAuthorize("hasAuthority('STUDENT')")
    @PostMapping("/{studentId}/events/{eventId}")
    public void addEventToStudent(@PathVariable Long studentId, @PathVariable Long eventId) {
        studentEventService.addEventToStudent(studentId, eventId);
    }

    @PreAuthorize("hasAuthority('STUDENT')")
    @DeleteMapping("/remove/student/{studentId}/event/{eventId}")
    public void removeEventFromStudent(@PathVariable("studentId") Long studentId, @PathVariable("eventId") Long eventId) {
        studentEventService.removeEventFromStudent(studentId, eventId);
    }
}

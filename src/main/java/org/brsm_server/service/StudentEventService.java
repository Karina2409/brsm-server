package org.brsm_server.service;

public interface StudentEventService {
    void addEventToStudent(Long studentId, Long eventId);
    void removeEventFromStudent(Long studentId, Long eventId);
}

package org.brsm_system_server.service.interfaces;

public interface IStudentEventService {
    void addEventToStudent(Long studentId, Long eventId);
    void removeEventFromStudent(Long studentId, Long eventId);
}

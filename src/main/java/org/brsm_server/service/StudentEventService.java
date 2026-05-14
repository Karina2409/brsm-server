package org.brsm_server.service;

import java.util.List;

public interface StudentEventService {
    void addEventToStudent(Long studentId, Long eventId);
    void removeEventFromStudent(Long studentId, Long eventId);
    List<Long> getRegisteredEventIds(Long studentId);
}

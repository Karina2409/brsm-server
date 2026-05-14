package org.brsm_server.service.impl;

import lombok.RequiredArgsConstructor;
import org.brsm_server.repository.StudentEventRepository;
import org.brsm_server.service.StudentEventService;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class StudentEventServiceImpl implements StudentEventService {
    private final StudentEventRepository studentEventRepository;

    @Override
    public void addEventToStudent(Long studentId, Long eventId) {
        studentEventRepository.addEventToStudent(studentId, eventId);
    }

    @Override
    public void removeEventFromStudent(Long studentId, Long eventId) {
        studentEventRepository.removeEventFromStudent(studentId, eventId);
    }

    @Override
    public List<Long> getRegisteredEventIds(Long studentId) {
        return studentEventRepository.findRegisteredEventIdsByStudentId(studentId);
    }
}

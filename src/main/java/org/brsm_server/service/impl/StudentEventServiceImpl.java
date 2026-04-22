package org.brsm_server.service.impl;

import org.brsm_server.repository.StudentEventRepository;
import org.brsm_server.service.StudentEventService;
import org.brsm_server.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class StudentEventServiceImpl implements StudentEventService {

    @Autowired
    private StudentEventRepository studentEventRepository;

    @Autowired
    private UserService userService;

    @Override
    public void addEventToStudent(Long studentId, Long eventId) {
        studentEventRepository.addEventToStudent(studentId, eventId);
    }

    @Override
    public void removeEventFromStudent(Long studentId, Long eventId) {
        studentEventRepository.removeEventFromStudent(studentId, eventId);
    }
}

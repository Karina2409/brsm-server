package org.brsm_system_server.service;

import org.brsm_system_server.repository.StudentEventRepository;
import org.brsm_system_server.service.interfaces.IStudentEventService;
import org.brsm_system_server.service.interfaces.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class StudentEventService implements IStudentEventService {

    @Autowired
    private StudentEventRepository studentEventRepository;

    @Autowired
    private IUserService userService;

    @Override
    public void addEventToStudent(Long studentId, Long eventId) {
        studentEventRepository.addEventToStudent(studentId, eventId);
    }

    @Override
    public void removeEventFromStudent(Long studentId, Long eventId) {
        studentEventRepository.removeEventFromStudent(studentId, eventId);
    }
}

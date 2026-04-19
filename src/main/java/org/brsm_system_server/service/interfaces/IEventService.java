package org.brsm_system_server.service.interfaces;

import org.brsm_system_server.entity.Event;
import org.brsm_system_server.entity.enums.FacultyEnum;
import org.springframework.http.ResponseEntity;

import java.util.Date;
import java.util.List;
import java.util.Map;

public interface IEventService {
    List<Event> findAllEvents();
    List<Event> getEventsByStudentId(Long studentId);
    Event getEventById(Long id);
    Event createEvent(Event event);
    List<Event> getPastEvents();
    ResponseEntity<Void> deleteEventById(Long event_id);
    List<Event> getEventByStudentIdPetition(Long studentId);
    Map<FacultyEnum, Long> countStudentsByFacultyBetweenDates(Date startDate, Date endDate);
    Date[] getDateRange(String period);
    List<Event> getUpcomingEventsWithAvailableSlots();
}

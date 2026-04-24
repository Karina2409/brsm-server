package org.brsm_server.service;

import org.brsm_server.dto.EventDTO;
import org.brsm_server.entity.Event;
import org.brsm_server.entity.enums.Faculty;

import java.util.Date;
import java.util.List;
import java.util.Map;

public interface EventService {
    List<Event> findAllEvents();
    Event getEventById(Long id);

    Event createEvent(EventDTO event);
    Event updateEvent(Long id, EventDTO dto);

    void deleteEventById(Long id);

    Map<Faculty, Long> getStatistics(String period);

    List<Event> getPastEvents();
    List<Event> getUpcomingEventsWithAvailableSlots();

    List<Event> getEventByStudentIdPetition(Long studentId);
    Map<Faculty, Long> countStudentsByFacultyBetweenDates(Date startDate, Date endDate);
    Date[] getDateRange(String period);
    List<Event> getEventsByStudentId(Long studentId);
}

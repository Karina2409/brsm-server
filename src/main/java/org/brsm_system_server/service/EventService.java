package org.brsm_system_server.service;

import org.brsm_system_server.entity.Event;
import org.brsm_system_server.entity.enums.FacultyEnum;
import org.brsm_system_server.repository.EventRepository;
import org.brsm_system_server.repository.StudentEventRepository;
import org.brsm_system_server.repository.StudentRepository;
import org.brsm_system_server.service.interfaces.IEventService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class EventService implements IEventService {

    @Autowired
    private EventRepository eventRepository;

    @Autowired
    private StudentEventRepository studentEventRepository;

    @Autowired
    private StudentRepository studentRepository;

    @Override
    public List<Event> findAllEvents(){
        return eventRepository.findAll(Sort.by(Sort.Direction.DESC, "eventDate"));
    }

    @Override
    public List<Event> getEventsByStudentId(Long studentId) {
        return eventRepository.findEventsByStudentId(studentId);
    }

    @Override
    public Event getEventById(Long id){
        Optional<Event> optionalEvent = eventRepository.findById(id);
        return optionalEvent.orElse(null);
    }

    @Override
    public Event createEvent(Event event) {
        return eventRepository.save(event);
    }

    @Override
    public List<Event> getEventByStudentIdPetition(Long studentId){
        return eventRepository.findPetitionEventsByStudentId(studentId);
    }

    @Override
    public List<Event> getPastEvents() {
        return eventRepository.findByEventDateBefore(new Date());
    }

    @Override
    public ResponseEntity<Void> deleteEventById(Long event_id) {
        Optional<Event> event = eventRepository.findById(event_id);
        if (event.isPresent()) {
            studentEventRepository.deleteByEventId(event_id);
            eventRepository.delete(event.get());
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @Override
    public Map<FacultyEnum, Long> countStudentsByFacultyBetweenDates(Date startDate, Date endDate) {
        List<Object[]> results = studentRepository.countStudentsByFacultyBetweenDates(startDate, endDate);
        return results.stream().collect(Collectors.toMap(
                result -> (FacultyEnum) result[0],
                result -> (Long) result[1]
        ));
    }

    @Override
    public Date[] getDateRange(String period) {
        Calendar calendar = Calendar.getInstance();
        Date endDate = calendar.getTime();
        Date startDate = null;

        switch (period) {
            case "month":
                calendar.add(Calendar.MONTH, -1);
                startDate = calendar.getTime();
                break;
            case "semester":
                int month = calendar.get(Calendar.MONTH);
                if (month < Calendar.SEPTEMBER && month >= Calendar.JANUARY) {
                    calendar.set(Calendar.MONTH, Calendar.JANUARY);
                } else {
                    calendar.set(Calendar.MONTH, Calendar.SEPTEMBER);
                }
                calendar.set(Calendar.DAY_OF_MONTH, 1);
                startDate = calendar.getTime();
                break;
            case "year":
                calendar.add(Calendar.YEAR, -1);
                startDate = calendar.getTime();
                break;
        }
        return new Date[]{startDate, endDate};
    }

    @Override
    public List<Event> getUpcomingEventsWithAvailableSlots() {
        Date currentDate = new Date();
        return eventRepository.findUpcomingEventsWithAvailableSlots(currentDate);
    }
}

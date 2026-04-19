package org.brsm_system_server.controller;

import org.brsm_system_server.dto.EventDTO;
import org.brsm_system_server.dto.StudentDTO;
import org.brsm_system_server.entity.Event;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.entity.enums.FacultyEnum;
import org.brsm_system_server.mapper.StudentMapper;
import org.brsm_system_server.service.interfaces.IEventService;
import org.brsm_system_server.service.interfaces.IStudentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.brsm_system_server.mapper.EventMapper;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@RestController
@RequestMapping("/events")
public class EventController {

    @Autowired
    private IEventService eventService;

    @Autowired
    private IStudentService studentService;

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/get-all")
    public List<EventDTO> getEvents() {
        List<Event> events = eventService.findAllEvents();
        return events.stream().map(EventMapper::toDto).toList();
    }

    @GetMapping("/{eventId}")
    public EventDTO getEventById(@PathVariable Long eventId) {
        Event event = eventService.getEventById(eventId);
        return EventMapper.toDto(event);
    }

    @GetMapping("/{eventId}/students")
    public List<StudentDTO> getStudentsByEventId(@PathVariable Long eventId) {
        List<Student> students = studentService.getStudentsByEventId(eventId);
        return students.stream().map(student -> {
            return StudentMapper.toDto(student, eventService);
        }).toList();
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PutMapping("/event/update/{eventId}")
    public ResponseEntity<?> updateEvent(@PathVariable Long eventId, @RequestBody Event updateEvent) {
        Event event = eventService.getEventById(eventId);
        System.out.println(updateEvent);
        System.out.println(event);
        if (event != null) {
            Date currentDate = new Date();
            System.out.println(event.getEventDate().after(currentDate));
            if (event.getEventDate().after(currentDate)) {
                event.setEventName(updateEvent.getEventName());
                if (updateEvent.getEventDate() != null) {
                    DateTimeFormatter formatter = DateTimeFormatter.ofPattern("EEE MMM dd HH:mm:ss zzz yyyy", Locale.ENGLISH);
                    LocalDate formattedDate = LocalDate.parse(updateEvent.getEventDate().toString(), formatter);
                    event.setEventDate(java.sql.Date.valueOf(formattedDate));
                }
                event.setEventTime(updateEvent.getEventTime());
                event.setEventPlace(updateEvent.getEventPlace());
                event.setStudentCount(updateEvent.getStudentCount());
                event.setOptCount(updateEvent.getOptCount());
                event.setForPetition(updateEvent.isForPetition());
                eventService.createEvent(event);
                return ResponseEntity.ok(event);
            } else {
                return ResponseEntity.badRequest().build();
            }

        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Мероприятие с указанным айди не найдено");
        }
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY', 'STUDENT')")
    @GetMapping("/past")
    public ResponseEntity<List<EventDTO>> getPastEvents() {
        List<Event> pastEvents = eventService.getPastEvents();
        return ResponseEntity.ok(pastEvents.stream().map(EventMapper::toDto).toList());
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @DeleteMapping("/delete/{eventId}")
    public ResponseEntity<Void> deleteEvent(@PathVariable Long eventId) {
        return eventService.deleteEventById(eventId);
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @PostMapping("/post")
    public ResponseEntity<Event> createEvent(@RequestBody Event event) {
        Event createdEvent = eventService.createEvent(event);
        return ResponseEntity.ok(createdEvent);
    }

    @PreAuthorize("hasAnyAuthority('SECRETARY', 'CHIEF_SECRETARY')")
    @GetMapping("/eventStatistics")
    public Map<FacultyEnum, Long> getEventStatistics(@RequestParam String period) {
        Date[] dateRange = eventService.getDateRange(period);
        System.out.println(eventService.countStudentsByFacultyBetweenDates(dateRange[0], dateRange[1]));
        return eventService.countStudentsByFacultyBetweenDates(dateRange[0], dateRange[1]);
    }

    @GetMapping("/upcoming")
    public List<Event> getUpcomingEventsWithAvailableSlots() {
        return eventService.getUpcomingEventsWithAvailableSlots();
    }
}

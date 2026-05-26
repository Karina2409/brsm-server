package org.brsm_server.controller;

import lombok.RequiredArgsConstructor;
import org.brsm_server.dto.EventDTO;
import org.brsm_server.dto.StudentFullNameDTO;
import org.brsm_server.entity.enums.Faculty;
import org.brsm_server.mapper.StudentMapper;
import org.brsm_server.security.Roles;
import org.brsm_server.service.EventService;
import org.brsm_server.service.StudentService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.brsm_server.mapper.EventMapper;

import java.util.Date;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/events")
@RequiredArgsConstructor
public class EventController {

    private final EventService eventService;
    private final StudentService studentService;
    private final EventMapper eventMapper;
    private final StudentMapper studentMapper;

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping
    public List<EventDTO> getEvents() {
        return eventService.findAllEvents()
                .stream()
                .map(eventMapper::toDto)
                .toList();
    }

    @PreAuthorize(Roles.ALL_AUTH)
    @GetMapping("/calendar")
    public List<EventDTO> getEventsForCalendar(
            @RequestParam int year,
            @RequestParam int month
    ) {
        return eventService.getEventsForCalendar(year, month);
    }

    @PreAuthorize(Roles.ALL_AUTH)
    @GetMapping("/{eventId}")
    public ResponseEntity<EventDTO> getEventById(@PathVariable Long eventId) {
        return ResponseEntity.ok(eventMapper.toDto(eventService.getEventById(eventId)));
    }

    //TODO: пересмотреть почему в маппере использовался eventService
    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping("/{eventId}/students")
    public List<StudentFullNameDTO> getStudentsByEventId(@PathVariable Long eventId) {
        return studentService.getStudentsByEventId(eventId)
                .stream()
                .map(studentMapper::toDtoFullName)
                .toList();
    }

    @PreAuthorize(Roles.SECRETARIES)
    @PutMapping("/{eventId}")
    public ResponseEntity<EventDTO> updateEvent(
            @PathVariable Long eventId,
            @RequestBody EventDTO dto
    ) {
        return ResponseEntity.ok(
                eventMapper.toDto(eventService.updateEvent(eventId, dto))
        );
    }

    @PreAuthorize(Roles.ALL_AUTH)
    @GetMapping("/past")
    public List<EventDTO> getPastEvents() {
        return eventService.getPastEvents()
                .stream()
                .map(eventMapper::toDto)
                .toList();
    }

    @PreAuthorize(Roles.SECRETARIES)
    @DeleteMapping("/{eventId}")
    public ResponseEntity<Void> deleteEvent(@PathVariable Long eventId) {
        eventService.deleteEventById(eventId);
        return ResponseEntity.noContent().build();
    }

    @PreAuthorize(Roles.SECRETARIES)
    @PostMapping
    public ResponseEntity<EventDTO> createEvent(@RequestBody EventDTO dto) {
        return ResponseEntity.ok(
                eventMapper.toDto(eventService.createEvent(dto))
        );
    }

    @PreAuthorize(Roles.SECRETARIES)
    @GetMapping("/statistics")
    public Map<Faculty, Long> getEventStatistics(@RequestParam String period) {
        return eventService.getStatistics(period);
    }

    @PreAuthorize(Roles.STUDENT)
    @GetMapping("/upcoming")
    public List<EventDTO> getUpcomingEvents() {
        return eventService.getUpcomingEventsWithAvailableSlots()
                .stream()
                .map(eventMapper::toDto)
                .toList();
    }

    @PreAuthorize(Roles.ALL_AUTH)
    @GetMapping("/by-date")
    public List<EventDTO> getEventsByDate(@RequestParam @org.springframework.format.annotation.DateTimeFormat(pattern="yyyy-MM-dd") Date date) {
        return eventService.getEventsByDate(date);
    }
}

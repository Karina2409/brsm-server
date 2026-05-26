package org.brsm_server.service.impl;

import lombok.RequiredArgsConstructor;
import org.brsm_server.dto.EventDTO;
import org.brsm_server.entity.Event;
import org.brsm_server.entity.User;
import org.brsm_server.entity.enums.Faculty;
import jakarta.persistence.EntityNotFoundException;
import org.brsm_server.mapper.EventMapper;
import org.brsm_server.repository.EventRepository;
import org.brsm_server.repository.StudentEventRepository;
import org.brsm_server.repository.StudentRepository;
import org.brsm_server.service.EventService;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import org.brsm_server.entity.enums.RoleEnum;

import java.time.LocalTime;
import java.time.YearMonth;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class EventServiceImpl implements EventService {

    private final EventRepository eventRepository;
    private final StudentEventRepository studentEventRepository;
    private final StudentRepository studentRepository;
    private final EventMapper eventMapper;

    @Override
    public List<Event> findAllEvents(){
        return eventRepository.findAllWithStudents(Sort.by(Sort.Direction.DESC, "date"));
    }

    @Override
    public List<Event> getEventsByStudentId(Long studentId) {
        return eventRepository.findEventsByStudentId(studentId);
    }

    @Override
    public Event getEventById(Long id){
        return eventRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    @Override
    public Event createEvent(EventDTO dto) {
        Event event = eventMapper.toEntity(dto);

        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        event.setCreatedBy(currentUser.getStudent());

        return eventRepository.save(event);
    }

    @Override
    public Event updateEvent(Long id, EventDTO dto) {
        Event event = eventRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Event not found"));

        event.setName(dto.getName());
        event.setDate(dto.getDate());
        event.setTime(dto.getTime());
        event.setPlace(dto.getPlace());
        event.setStudentCount(dto.getStudentCount());
        event.setOptCount(dto.getOptCount());
        event.setForPetition(dto.isForPetition());

        return eventRepository.save(event);
    }

    @Override
    public List<Event> getEventByStudentIdPetition(Long studentId){
        return eventRepository.findPetitionEventsByStudentId(studentId);
    }

    @Override
    public List<Event> getPastEvents() {
        return eventRepository.findAllByDateBefore(new Date());
    }

    @Override
    public void deleteEventById(Long eventId) {
        Event event = eventRepository.findById(eventId)
                .orElseThrow(() -> new EntityNotFoundException("Event not found"));

        studentEventRepository.deleteByEventId(eventId);
        eventRepository.delete(event);
    }

    @Override
    public Map<Faculty, Long> getStatistics(String period) {
        Date[] range = getDateRange(period);
        return countStudentsByFacultyBetweenDates(range[0], range[1]);
    }

    @Override
    public Map<Faculty, Long> countStudentsByFacultyBetweenDates(Date startDate, Date endDate) {
        List<Object[]> results = studentRepository.countStudentsByFacultyBetweenDates(startDate, endDate);
        return results.stream().collect(Collectors.toMap(
                result -> (Faculty) result[0],
                result -> (Long) result[1]
        ));
    }

    @Override
    public Date[] getDateRange(String period) {
        Calendar calendar = Calendar.getInstance();
        Date endDate = calendar.getTime();
        Date startDate;

        switch (period) {
            case "week":
                calendar.add(Calendar.DAY_OF_YEAR, -7);
                startDate = calendar.getTime();
                break;
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
            case "all":
                calendar.set(1970, Calendar.JANUARY, 1);
                startDate = calendar.getTime();
                break;
            default:
                return new Date[]{new Date(0), endDate};
        }
        return new Date[]{startDate, endDate};
    }

    @Override
    public List<Event> getUpcomingEventsWithAvailableSlots() {
        Date currentDate = new Date();
        LocalTime currentTime = LocalTime.now();
        return eventRepository.findUpcomingEventsWithAvailableSlots(currentDate, currentTime);
    }

    @Override
    public List<EventDTO> getEventsForCalendar(int year, int month) {
        YearMonth yearMonth = YearMonth.of(year, month);
        Date startDate = java.sql.Date.valueOf(yearMonth.atDay(1));
        Date endDate = java.sql.Date.valueOf(yearMonth.atEndOfMonth());

        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        RoleEnum role = currentUser.getRole();

        List<Event> events;
        if (role == RoleEnum.SECRETARY || role == RoleEnum.CHIEF_SECRETARY) {
            events = eventRepository.findAllByDateBetween(startDate, endDate);
        } else {
            Long studentId = currentUser.getStudent().getStudentId();
            events = eventRepository.findEventsByStudentIdAndDateBetween(studentId, startDate, endDate);
        }

        return events.stream()
                .map(eventMapper::toDto)
                .toList();
    }

    @Override
    public List<EventDTO> getEventsByDate(Date date) {
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        RoleEnum role = currentUser.getRole();

        List<Event> events;
        if (role == RoleEnum.SECRETARY || role == RoleEnum.CHIEF_SECRETARY) {
            events = eventRepository.findAllByDate(date);
        } else {
            Long studentId = currentUser.getStudent().getStudentId();
            events = eventRepository.findEventsByStudentIdAndDate(studentId, date);
        }

        return events.stream()
                .map(eventMapper::toDto)
                .toList();
    }
}

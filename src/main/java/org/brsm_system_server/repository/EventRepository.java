package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Event;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Date;
import java.util.List;

public interface EventRepository extends JpaRepository<Event, Long> {

    @Query("SELECT e FROM Event e JOIN e.students s WHERE s.studentId = :studentId")
    List<Event> findEventsByStudentId(@Param("studentId") Long studentId);

    @Query("SELECT e FROM Event e WHERE e.eventDate > :currentDate AND e.studentCount > (SELECT COUNT(s) FROM e.students s) ORDER BY e.eventDate ASC")
    List<Event> findUpcomingEventsWithAvailableSlots(Date currentDate);

    @Query("SELECT e FROM Event e JOIN e.students s WHERE s.studentId = :studentId AND e.forPetition = true")
    List<Event> findPetitionEventsByStudentId(@Param("studentId") Long studentId);

    List<Event> findByEventDateBefore(Date now);
}

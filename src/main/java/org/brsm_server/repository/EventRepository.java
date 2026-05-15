package org.brsm_server.repository;

import org.brsm_server.entity.Event;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Date;
import java.util.List;

public interface EventRepository extends JpaRepository<Event, Long> {

    @Query("SELECT DISTINCT e FROM Event e LEFT JOIN FETCH e.students WHERE e.deleted = false")
    List<Event> findAllWithStudents(Sort sort);

    @Query("SELECT e FROM Event e JOIN e.students s WHERE s.studentId = :studentId")
    List<Event> findEventsByStudentId(@Param("studentId") Long studentId);

    @Query("""
        SELECT e FROM Event e
        LEFT JOIN e.students s
        WHERE e.date > :currentDate
            GROUP BY e
            HAVING e.studentCount > COUNT(s)
            ORDER BY e.date ASC
        """)
    List<Event> findUpcomingEventsWithAvailableSlots(@Param("currentDate") Date currentDate);

    @Query("SELECT e FROM Event e JOIN e.students s WHERE s.studentId = :studentId AND e.forPetition = true")
    List<Event> findPetitionEventsByStudentId(@Param("studentId") Long studentId);

    List<Event> findAllByDateBefore(Date now);
}

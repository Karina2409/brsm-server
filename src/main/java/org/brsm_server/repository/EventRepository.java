package org.brsm_server.repository;

import org.brsm_server.entity.Event;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalTime;
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
           OR (e.date = :currentDate AND e.time > :currentTime)
            GROUP BY e
            HAVING e.studentCount > COUNT(s)
            ORDER BY e.date ASC
        """)
    List<Event> findUpcomingEventsWithAvailableSlots(@Param("currentDate") Date currentDate, @Param("currentTime") LocalTime currentTime);

    @Query("SELECT e FROM Event e JOIN e.students s WHERE s.studentId = :studentId AND e.forPetition = true")
    List<Event> findPetitionEventsByStudentId(@Param("studentId") Long studentId);

    List<Event> findAllByDateBefore(Date now);

    @Query("SELECT DISTINCT e FROM Event e LEFT JOIN FETCH e.students WHERE e.deleted = false AND e.date BETWEEN :startDate AND :endDate ORDER BY e.date ASC")
    List<Event> findAllByDateBetween(@Param("startDate") Date startDate, @Param("endDate") Date endDate);

    @Query("SELECT e FROM Event e JOIN e.students s WHERE s.studentId = :studentId AND e.date BETWEEN :startDate AND :endDate ORDER BY e.date ASC")
    List<Event> findEventsByStudentIdAndDateBetween(@Param("studentId") Long studentId, @Param("startDate") Date startDate, @Param("endDate") Date endDate);

    @Query("SELECT DISTINCT e FROM Event e LEFT JOIN FETCH e.students WHERE e.deleted = false AND e.date = :date ORDER BY e.time ASC")
    List<Event> findAllByDate(@Param("date") Date date);

    @Query("SELECT e FROM Event e JOIN e.students s WHERE s.studentId = :studentId AND e.date = :date ORDER BY e.time ASC")
    List<Event> findEventsByStudentIdAndDate(@Param("studentId") Long studentId, @Param("date") Date date);
}

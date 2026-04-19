package org.brsm_server.mapper;

import org.brsm_server.dto.EventDTO;
import org.brsm_server.entity.Event;

public class EventMapper {

    public static EventDTO toDto(Event event) {
        return new EventDTO(
                event.getEventId(),
                event.getEventName(),
                event.getEventDate(),
                event.getEventTime(),
                event.getEventPlace(),
                event.getStudentCount(),
                event.getOptCount(),
                event.isForPetition()
        );
    }
}

package org.brsm_server.mapper;

import org.brsm_server.dto.EventDTO;
import org.brsm_server.entity.Event;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import java.time.OffsetDateTime;
import java.util.Date;

@Mapper(componentModel = "spring")
public interface EventMapper {

    @Mapping(target = "createdBy",
            expression = "java(event.getCreatedBy() != null ? event.getCreatedBy().getShortFio() : null)")
    @Mapping(target = "studentsRegistered",
            expression = "java(event.getStudents() != null ? event.getStudents().size() : 0)")
    EventDTO toDto(Event event);

    @Mapping(target = "students", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "templateUsed", ignore = true)
    @Mapping(target = "deleted", ignore = true)
    @Mapping(target = "exceptions", ignore = true)
    @Mapping(target = "createdBy", ignore = true)
    Event toEntity(EventDTO dto);

    default Date map(OffsetDateTime value) {
        return value == null ? null : Date.from(value.toInstant());
    }
}

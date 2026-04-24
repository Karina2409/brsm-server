package org.brsm_server.mapper;

import org.brsm_server.dto.EventDTO;
import org.brsm_server.entity.Event;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface EventMapper {

    EventDTO toDto(Event event);

    @Mapping(target = "students", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "templateUsed", ignore = true)
    @Mapping(target = "deleted", ignore = true)
    @Mapping(target = "exceptions", ignore = true)
    Event toEntity(EventDTO dto);
}

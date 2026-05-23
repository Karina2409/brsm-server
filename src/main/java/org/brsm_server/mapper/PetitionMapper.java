package org.brsm_server.mapper;

import org.brsm_server.dto.PetitionDTO;
import org.brsm_server.entity.Petition;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface PetitionMapper {

    @Mapping(source = "documentId", target = "documentId")
    @Mapping(source = "name", target = "name")
    @Mapping(source = "studentFaculty", target = "studentFaculty")
    @Mapping(target = "date", expression = "java(petition.getCreatedAt() != null ? java.util.Date.from(petition.getCreatedAt().toInstant()) : null)")
    PetitionDTO toDto(Petition petition);
}

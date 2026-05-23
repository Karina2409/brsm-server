package org.brsm_server.mapper;

import org.brsm_server.dto.ExemptionDTO;
import org.brsm_server.entity.Exemption;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface ExemptionMapper {

    @Mapping(source = "documentId", target = "documentId")
    @Mapping(source = "name", target = "name")
    @Mapping(source = "studentFaculty", target = "studentFaculty")
    @Mapping(target = "date", expression = "java(exemption.getCreatedAt() != null ? java.util.Date.from(exemption.getCreatedAt().toInstant()) : null)")
    ExemptionDTO toDto(Exemption exemption);
}

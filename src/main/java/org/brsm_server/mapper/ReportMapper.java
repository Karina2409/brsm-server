package org.brsm_server.mapper;

import org.brsm_server.dto.ReportDTO;
import org.brsm_server.entity.Report;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface ReportMapper {
    @Mapping(source = "documentId", target = "documentId")
    @Mapping(source = "name", target = "name")
    @Mapping(source = "dormNumber", target = "dormNumber")
    @Mapping(target = "date", expression = "java(report.getCreatedAt() != null ? java.util.Date.from(report.getCreatedAt().toInstant()) : null)")
    ReportDTO toDto(Report report);
}

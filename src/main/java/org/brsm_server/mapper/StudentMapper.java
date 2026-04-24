package org.brsm_server.mapper;

import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.Student;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface StudentMapper {
    StudentDTO toDto(Student student);

    Student toEntity(StudentDTO dto);
}

package org.brsm_server.mapper;

import org.brsm_server.dto.CreateStudentRequestDTO;
import org.brsm_server.dto.SecretaryDTO;
import org.brsm_server.dto.StudentDTO;
import org.brsm_server.dto.StudentFullNameDTO;
import org.brsm_server.entity.Student;
import org.brsm_server.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface StudentMapper {
    @Mapping(target = "studentId", source = "studentId")
    @Mapping(target = "eventsCount", expression = "java(student.getEvents() != null ? student.getEvents().size() : 0)")
    StudentDTO toDto(Student student);

    StudentFullNameDTO toDtoFullName(Student student);

    @Mapping(target = "surname", source = "student.surname")
    @Mapping(target = "name", source = "student.name")
    @Mapping(target = "patronymic", source = "student.patronymic")
    @Mapping(target = "faculty", source = "student.faculty")
    @Mapping(target = "telegramUsername", source = "student.telegramUsername")
    @Mapping(target = "photo", source = "student.photo")
    @Mapping(target = "role", source = "role")
    SecretaryDTO toSecretaryDto(User user);

    Student toEntity(StudentDTO dto);

    @Mapping(target = "studentId", ignore = true)
    @Mapping(target = "events", ignore = true)
    @Mapping(target = "exception", ignore = true)
    @Mapping(target = "reports", ignore = true)
    Student toEntity(CreateStudentRequestDTO dto);
}

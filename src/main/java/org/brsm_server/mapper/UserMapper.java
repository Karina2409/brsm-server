package org.brsm_server.mapper;

import org.brsm_server.dto.UserDTO;
import org.brsm_server.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {
    @Mapping(target = "userId", source = "userId")
    @Mapping(target = "surname", source = "student.surname")
    @Mapping(target = "name", source = "student.name")
    @Mapping(target = "patronymic", source = "student.patronymic")
    @Mapping(target = "groupNumber", source = "student.groupNumber")
    @Mapping(target = "faculty", source = "student.faculty")
    UserDTO toDto(User user);

    User toEntity(UserDTO userDTO);
}

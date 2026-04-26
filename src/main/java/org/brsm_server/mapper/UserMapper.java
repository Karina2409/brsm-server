package org.brsm_server.mapper;

import org.brsm_server.dto.UserDTO;
import org.brsm_server.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface UserMapper {
    @Mapping(target = "userId", source = "userId")
    @Mapping(target = "lastName", source = "student.lastName")
    @Mapping(target = "firstName", source = "student.firstName")
    @Mapping(target = "patronymic", source = "student.patronymic")
    UserDTO toDto(User user);

    User toEntity(UserDTO userDTO);
}

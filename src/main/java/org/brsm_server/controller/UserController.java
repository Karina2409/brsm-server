package org.brsm_server.controller;

import lombok.RequiredArgsConstructor;
import org.brsm_server.dto.StudentDTO;
import org.brsm_server.dto.UserDTO;
import org.brsm_server.entity.User;
import org.brsm_server.entity.enums.RoleEnum;
import org.brsm_server.mapper.UserMapper;
import org.brsm_server.security.Roles;
import org.brsm_server.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final UserMapper userMapper;

    @PreAuthorize(Roles.CHIEF)
    @GetMapping
    public List<UserDTO> getUsers() {
        List<User> users = userService.findAllUsers();
        return users.stream().map(userMapper::toDto).toList();
    }

    @PreAuthorize(Roles.ALL_AUTH)
    @GetMapping("/student/{userId}")
    public StudentDTO getStudent(@PathVariable Long userId) {
        return userService.findStudentById(userId);
    }

    @PreAuthorize(Roles.CHIEF)
    @PatchMapping("/{userId}")
    public ResponseEntity<Void> changeUserRole(
            @PathVariable Long userId,
            @RequestBody Map<String, String> payload,
            @RequestParam(value = "force", defaultValue = "false") boolean force) {

        String role = payload.get("role");
        if (role == null) {
            return ResponseEntity.badRequest().build();
        }

        RoleEnum newRole = RoleEnum.valueOf(role);
        userService.changeUserRole(userId, newRole,  force);
        return ResponseEntity.ok().build();
    }
}

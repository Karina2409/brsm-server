package org.brsm_server.mapper;

import org.brsm_server.dto.StudentDTO;
import org.brsm_server.entity.Student;
import org.brsm_server.service.EventService;

public class StudentMapper {

    public static StudentDTO toDto(Student student, EventService eventService) {

        return new StudentDTO(student.getStudentId(),
                student.getFullNameDative(),
                student.getLastName(),
                student.getFirstName(),
                student.getPatronymic(),
                student.getGroupNumber(),
                student.getFaculty(),
                student.isDormitoryResidence(),
                student.getDormBlockNumber(),
                student.getDormNumber(),
                eventService.getEventsByStudentId(student.getStudentId()).size(),
                student.isBrsmMember(),
                student.getPhoneNumber(),
                student.getTelegramUsername(),
                student.getPhoto());
    }

    public static Student toEntity(StudentDTO studentDTO) {
        Student student = new Student();
        student.setStudentId(studentDTO.getStudentId());
        student.setFullNameDative(studentDTO.getFullNameDative());
        student.setLastName(studentDTO.getLastName());
        student.setFirstName(studentDTO.getFirstName());
        student.setPatronymic(studentDTO.getPatronymic());
        student.setGroupNumber(studentDTO.getGroupNumber());
        student.setFaculty(studentDTO.getFaculty());
        student.setDormitoryResidence(studentDTO.isDormitoryResidence());
        student.setDormBlockNumber(studentDTO.getDormBlockNumber());
        student.setDormNumber(studentDTO.getDormNumber());
        return student;
    }
}

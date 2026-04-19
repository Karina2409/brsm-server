package org.brsm_system_server.mapper;

import org.brsm_system_server.dto.StudentDTO;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.service.interfaces.IEventService;

public class StudentMapper {

    public static StudentDTO toDto(Student student, IEventService eventService) {

        return new StudentDTO(student.getStudentId(),
                student.getStudentFullNameD(),
                student.getLastName(),
                student.getFirstName(),
                student.getMiddleName(),
                student.getGroupNumber(),
                student.getStudentFaculty(),
                student.isDormitoryResidence(),
                student.getDormBlockNumber(),
                student.getDormNumber(),
                eventService.getEventsByStudentId(student.getStudentId()).size(),
                student.isBrsmMember(),
                student.getPhoneNumber(),
                student.getTelegram(),
                student.getImage());
    }

    public static Student toEntity(StudentDTO studentDTO) {
        Student student = new Student();
        student.setStudentId(studentDTO.getStudentId());
        student.setStudentFullNameD(studentDTO.getStudentFullNameD());
        student.setLastName(studentDTO.getLastName());
        student.setFirstName(studentDTO.getFirstName());
        student.setMiddleName(studentDTO.getMiddleName());
        student.setGroupNumber(studentDTO.getGroupNumber());
        student.setStudentFaculty(studentDTO.getStudentFaculty());
        student.setDormitoryResidence(studentDTO.isDormitoryResidence());
        student.setDormBlockNumber(studentDTO.getDormBlockNumber());
        student.setDormNumber(studentDTO.getDormNumber());
        return student;
    }
}

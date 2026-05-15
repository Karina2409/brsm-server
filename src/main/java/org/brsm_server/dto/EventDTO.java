package org.brsm_server.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalTime;
import java.util.Date;

@Data
@AllArgsConstructor
public class EventDTO {
    private Long eventId;

    private String name;

    @JsonFormat(pattern = "yyyy-MM-dd", timezone = "Europe/Minsk")
    private Date date;

    @JsonFormat(pattern = "HH:mm", timezone = "Europe/Minsk")
    private LocalTime time;
    private String place;
    private int studentCount;
    private int studentsRegistered;
    private int optCount;
    private boolean forPetition;
    private Date createdAt;
    private String createdBy;
}

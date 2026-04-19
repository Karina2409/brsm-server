package org.brsm_system_server.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.sql.Time;
import java.util.Date;

@Data
@AllArgsConstructor
public class EventDTO {
    private Long eventId;

    private String eventName;

    @JsonFormat(pattern = "yyyy-MM-dd", timezone = "Europe/Minsk")
    private Date eventDate;

    @JsonFormat(pattern = "HH:mm", timezone = "Europe/Minsk")
    private Time eventTime;
    private String eventPlace;
    private int studentCount;
    private int optCount;
    private boolean forPetition;
}

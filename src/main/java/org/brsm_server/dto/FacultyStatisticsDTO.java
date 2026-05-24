package org.brsm_server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.brsm_server.entity.enums.Faculty;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class FacultyStatisticsDTO {

    private Faculty faculty;
    private Long studentCount;
}

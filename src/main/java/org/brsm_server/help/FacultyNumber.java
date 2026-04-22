package org.brsm_server.help;

import org.brsm_server.entity.enums.Faculty;

import java.util.HashMap;
import java.util.Map;

public class FacultyNumber {

    public static Faculty getFacultyNameByNum(Integer facultyNumber) {
        Map<Integer, Faculty> facultyMap = new HashMap<>();
        facultyMap.put(1, Faculty.ФКП);
        facultyMap.put(2, Faculty.ФИТУ);
        facultyMap.put(3, Faculty.ФРЭ);
        facultyMap.put(4, Faculty.ФКСИС);
        facultyMap.put(5, Faculty.ИЭФ);
        facultyMap.put(6, Faculty.ФИБ);
        facultyMap.put(7, Faculty.ВФ);

        return facultyMap.get(facultyNumber);
    }
}

package org.brsm_server.entity;

import org.brsm_server.entity.enums.Faculty;

import java.util.HashMap;
import java.util.Map;

import static org.brsm_server.entity.enums.Faculty.*;

public class DeanData {
    private static final Map<Faculty, String> facultyDeanMap = new HashMap<>();

    static {
        facultyDeanMap.put(ФКП, "Лихачевскому Д.В.");
        facultyDeanMap.put(ФИТУ, "Шилину Л.Ю.");
        facultyDeanMap.put(ФКСИС, "Ульянову Н.И.");
        facultyDeanMap.put(ИЭФ, "Лавровой О.И.");
        facultyDeanMap.put(ФИБ, "Дроботу С.В.");
        facultyDeanMap.put(ФРЭ, "Гранько С.В.");
        facultyDeanMap.put(ВФ, "Колегаеву В.Г.");
    }

    public static String getFacultyDean(Faculty faculty) {
        return facultyDeanMap.get(faculty);
    }
}

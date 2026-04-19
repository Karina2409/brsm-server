package org.brsm_system_server.help;

import java.text.SimpleDateFormat;
import java.util.Date;

public class DateFormat {

    public static String DateDotFormat (Date date){
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy");
        return dateFormat.format(date);
    }

    public static String Date_Format (Date date){
        SimpleDateFormat dateFormat = new SimpleDateFormat("dd_MM_yyyy");
        return dateFormat.format(date);
    }
}

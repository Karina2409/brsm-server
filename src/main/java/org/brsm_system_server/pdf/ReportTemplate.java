package org.brsm_system_server.pdf;

import org.brsm_system_server.help.DateFormat;

import java.util.Date;

public class ReportTemplate {
    public String generateContent(StringBuilder studentsInfo) {

        return  "Прошу Вас зачесть часы общественно "
                + "полезного труда в количестве часов за активную работу в качестве "
                + "активиста ПО ОО «БРСМ» с правами РК БГУИР, за систематическое "
                + "участие в мероприятиях университета, а также в мероприятиях "
                + "городского и республиканского уровня:\n" + studentsInfo;
    }

    public String generateBeforeContent(Date reportDate){
        return "\n\nДОКЛАДНАЯ ЗАПИСКА\n" + DateFormat.DateDotFormat(reportDate)
                + "\n" + "г. Минск\n\n";
    }
}

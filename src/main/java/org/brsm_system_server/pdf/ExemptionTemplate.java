package org.brsm_system_server.pdf;

import org.brsm_system_server.entity.Event;
import org.brsm_system_server.entity.enums.FacultyEnum;
import org.brsm_system_server.help.DateFormat;
import org.brsm_system_server.repository.EventRepository;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class ExemptionTemplate {

    private final EventRepository eventRepository;

    public ExemptionTemplate(final EventRepository eventRepository) {
        this.eventRepository = eventRepository;
    }

    public String generateContent(StringBuilder studentsInfo, Long eventId) {

        Event event = eventRepository.findById(eventId).get();

        String eventName = event.getEventName();
        Date eventDate = event.getEventDate();

        return  "Прошу пропуски студента " + studentsInfo + " " + DateFormat.DateDotFormat(eventDate) +
                " считать по уважительной причине в связи с тем, что он принимал участие в " +
                eventName + ".\n\n\n\n\n\n\n\n";
    }

    public String generateHeader(FacultyEnum faculty, String recipient) {
        return "Декану " + faculty + "\n" + recipient;
    }

    public String generateBeforeContent(){
        return "\n\n\n\n" +
                "ДОКЛАДНАЯ ЗАПИСКА" + "\n" +
                DateFormat.DateDotFormat(new Date()) + "\n\n\n";
    }

}

package org.brsm_server.pdf;

import org.brsm_server.entity.Event;
import org.brsm_server.entity.enums.Faculty;
import org.brsm_server.help.DateFormat;
import org.brsm_server.repository.EventRepository;
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

        String eventName = event.getName();
        Date eventDate = event.getDate();

        return  "Прошу пропуски студента " + studentsInfo + " " + DateFormat.DateDotFormat(eventDate) +
                " считать по уважительной причине в связи с тем, что он принимал участие в " +
                eventName + ".\n\n\n\n\n\n\n\n";
    }

    public String generateHeader(Faculty faculty, String recipient) {
        return "Декану " + faculty + "\n" + recipient;
    }

    public String generateBeforeContent(){
        return "\n\n\n\n" +
                "ДОКЛАДНАЯ ЗАПИСКА" + "\n" +
                DateFormat.DateDotFormat(new Date()) + "\n\n\n";
    }

}

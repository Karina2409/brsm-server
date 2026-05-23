package org.brsm_server.service.impl;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.brsm_server.entity.DeanData;
import org.brsm_server.entity.Event;
import org.brsm_server.entity.Exemption;
import org.brsm_server.entity.Student;
import org.brsm_server.entity.enums.Faculty;
import org.brsm_server.exception.EntityExistsException;
import org.brsm_server.help.DateFormat;
import org.brsm_server.pdf.ExemptionTemplate;
import org.brsm_server.pdf.PdfGenerator;
import org.brsm_server.repository.EventRepository;
import org.brsm_server.repository.ExemptionRepository;
import org.brsm_server.repository.ExemptionStudentsRepository;
import org.brsm_server.repository.StudentRepository;
import org.brsm_server.service.ExemptionService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@Service
@RequiredArgsConstructor
public class ExemptionServiceImpl implements ExemptionService {

    private final ExemptionRepository exemptionRepository;
    private final StudentRepository studentRepository;
    private final ExemptionStudentsRepository exemptionStudentsRepository;
    private final EventRepository eventRepository;

    @Override
    public List<Exemption> getAllExemptions() {
        return exemptionRepository.findAllActive();
    }

    @Override
    @Transactional
    public void saveExemption(Long eventId, Set<Long> studentIds) {
        List<Student> students = studentRepository.findAllById(studentIds);

        Set<Faculty> faculties = new HashSet<>();
        for (Student student : students) {
            faculties.add(student.getFaculty());
        }

        for (Faculty faculty : faculties) {

            String fileName = "освобождение_" + DateFormat.Date_Format(new Date()) + "_" + faculty + ".pdf";

            Exemption exemption = new Exemption();
            exemption.setName(fileName);
            exemption.setStudentFaculty(faculty);

            Optional<Event> event = eventRepository.findById(eventId);
            if (event.isEmpty()) {
                throw new EntityExistsException("Event not found with id: " + eventId);
            }
            exemption.setEvent(event.get());
            exemption.setEventName(event.get().getName());

            exemption = exemptionRepository.save(exemption);

            for (Student student : students) {
                if (student.getFaculty().equals(faculty)) {
                    exemptionStudentsRepository.saveExemptionStudent(exemption.getDocumentId(), student.getStudentId());
                }
            }
        }
    }

    @Override
    @Transactional
    public ResponseEntity<Void> deleteExemptionById(Long exemptionId) {
        Optional<Exemption> exemptionOpt = exemptionRepository.findById(exemptionId);
        if (exemptionOpt.isPresent()) {
            Exemption exemption = exemptionOpt.get();
            exemption.setDeleted(true);
            exemptionRepository.save(exemption);
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @Override
    public byte[] downloadExemption(Long exemptionId) {
        PdfGenerator pdfGenerator = new PdfGenerator();
        ExemptionTemplate exemptionTemplate = new ExemptionTemplate(eventRepository);
        String directoryName = "D:/BRSM project/документация/освобождения";
        Path directoryPath = Paths.get(directoryName);

        Exemption exemption = exemptionRepository.findById(exemptionId)
                .orElseThrow(() -> new EntityExistsException("Документ не найден"));

        Set<Student> students = exemptionStudentsRepository.findStudentsByExemptionId(exemptionId);
        Faculty faculty = exemption.getStudentFaculty();

        List<Student> filteredStudents = students.stream()
                .filter(student -> student.getFaculty().equals(faculty))
                .toList();

        StringBuilder studentsInfo = new StringBuilder();
        int k = 0;
        String exemptionHeader = exemptionTemplate.generateHeader(faculty,
                DeanData.getFacultyDean(faculty));

        for (Student student : filteredStudents) {
            if (k != 0) {
                studentsInfo.append(", ");
            }
            studentsInfo.append("гр. ")
                    .append(student.getGroupNumber())
                    .append(" ")
                    .append(student.getSurname())
                    .append(" ")
                    .append(student.getName())
                    .append(" ")
                    .append(student.getPatronymic());
            k++;

        }

        String exemptionContent = exemptionTemplate.generateContent(
                studentsInfo,
                exemption.getEvent().getEventId()
        );

        try {
            if (!Files.exists(directoryPath)) {
                Files.createDirectories(directoryPath);
            }
            String fileName = directoryName + "/освобождение_" + DateFormat.Date_Format(
                    Date.from(exemption.getCreatedAt().toInstant())) + "_" + faculty + ".pdf";
            float[] columnWidths = {3, 1};
            pdfGenerator.createPDF(fileName, exemptionHeader, exemptionTemplate.generateBeforeContent(), exemptionContent, columnWidths);

            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                PdfWriter writer = new PdfWriter(outputStream);
                PdfDocument pdfDocument = new PdfDocument(writer);
                Document document = new Document(pdfDocument)) {
                document.add(new Paragraph(exemptionContent));
            }

            return Files.readAllBytes(Paths.get(fileName));

        } catch (IOException e) {
            return new byte[0];
        }
    }
}

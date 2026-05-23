package org.brsm_server.service.impl;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.brsm_server.entity.Event;
import org.brsm_server.entity.Petition;
import org.brsm_server.entity.Student;
import org.brsm_server.exception.EntityExistsException;
import org.brsm_server.exception.PdfGenerationException;
import org.brsm_server.help.DateFormat;
import org.brsm_server.pdf.PdfGenerator;
import org.brsm_server.pdf.PetitionTemplate;
import org.brsm_server.repository.EventRepository;
import org.brsm_server.repository.PetitionRepository;
import org.brsm_server.repository.StudentRepository;
import org.brsm_server.service.PetitionService;
import org.brsm_server.service.StudentService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PetitionServiceImpl implements PetitionService {

    private final PetitionRepository petitionRepository;
    private final StudentRepository studentRepository;
    private final EventRepository eventRepository;
    private final StudentService studentService;

    @Override
    public List<Petition> getAllPetitions() {
        return petitionRepository.findAllActive();
    }

    @Override
    @Transactional
    public Petition savePetition(Long studentId) {
        Student student = studentRepository.findById(studentId)
                .orElseThrow(() -> new EntityExistsException("Студент не найден"));

        String fileName = "ходатайство_" + DateFormat.Date_Format(new Date()) + "_"
                + student.getSurname() + ".pdf";

        Petition petition = new Petition();
        petition.setName(fileName);
        petition.setStudentFaculty(student.getFaculty());
        petition.setStudentLastName(student.getSurname());
        petition.setStudent(student);

        return petitionRepository.save(petition);
    }

    @Override
    public ResponseEntity<Void> deletePetitionById(Long id) {
        Optional<Petition> petitionOpt = petitionRepository.findById(id);
        if (petitionOpt.isPresent()) {
            Petition petition = petitionOpt.get();
            petition.setDeleted(true);
            petitionRepository.save(petition);
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @Override
    public byte[] downloadPetition(Long petitionId) {
        PdfGenerator pdfGenerator = new PdfGenerator();
        Petition petition = petitionRepository.findById(petitionId)
                .orElseThrow(() -> new EntityExistsException("Документ не найден"));

        String directoryName = "D:/BRSM project/документация/ходатайства";
        Path directoryPath = Paths.get(directoryName);
        PetitionTemplate petitionTemplate = new PetitionTemplate(studentRepository, eventRepository);

        Long studentId = petition.getStudent().getStudentId();
        Student student = studentRepository.findById(studentId)
                .orElseThrow(() -> new EntityExistsException("Студент для документа не найден"));

        List<Event> petitionEvents = eventRepository.findPetitionEventsByStudentId(studentId);
        if (petitionEvents.isEmpty()) {
            return new byte[0];
        }

        String petitionContent = petitionTemplate.generateContent(studentId);

        try {
            if (!Files.exists(directoryPath)) {
                Files.createDirectories(directoryPath);
            }

            String fullPathString = directoryName + "/ходатайство_" + DateFormat.Date_Format(Date.from(petition.getCreatedAt().toInstant())) + "_"
                    + student.getSurname() + ".pdf";

            String petitionHeader = "Проректору по\nвоспитательной работе\nКузнецову Д.Ф.\n\n\n\n";
            float[] columnWidths = {5, 2};

            pdfGenerator.createPDF(fullPathString, petitionHeader, petitionTemplate.generateBeforeContent(), petitionContent, columnWidths);

            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                PdfWriter writer = new PdfWriter(outputStream);
                PdfDocument pdfDocument = new PdfDocument(writer);
                Document document = new Document(pdfDocument)) {
                document.add(new Paragraph(petitionContent));
            }

            return Files.readAllBytes(Paths.get(fullPathString));
        } catch (IOException e) {
            throw new PdfGenerationException("Ошибка чтения сгенерированного файла PDF", e);
        }
    }

    @Override
    public List<Student> getEligibleStudentsToPetition() {
        List<Student> eligibleStudents = studentService.findEligibleStudents();
        List<Student> eligibleStudentsToPetition = new ArrayList<>();
        for(Student student : eligibleStudents){
            if(petitionRepository.existsStudentInPetitions(student.getStudentId())){
                eligibleStudentsToPetition.add(student);
            }
        }
        return eligibleStudentsToPetition;
    }
}

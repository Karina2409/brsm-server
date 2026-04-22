package org.brsm_server.service.impl;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import jakarta.transaction.Transactional;
import org.brsm_server.entity.Event;
import org.brsm_server.entity.Petition;
import org.brsm_server.entity.Student;
import org.brsm_server.help.DateFormat;
import org.brsm_server.pdf.PdfGenerator;
import org.brsm_server.pdf.PetitionTemplate;
import org.brsm_server.repository.EventRepository;
import org.brsm_server.repository.PetitionRepository;
import org.brsm_server.repository.StudentRepository;
import org.brsm_server.service.PetitionService;
import org.brsm_server.service.StudentService;
import org.springframework.beans.factory.annotation.Autowired;
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
public class PetitionServiceImpl implements PetitionService {

    @Autowired
    private PetitionRepository petitionRepository;

    @Autowired
    private StudentRepository studentRepository;

    @Autowired
    private EventRepository eventRepository;

    @Autowired
    private StudentService studentService;

    @Override
    public List<Petition> getAllPetitions() {
        return petitionRepository.findAll();
    }

    @Override
    @Transactional
    public Petition savePetition(Long studentId) {

        Student student = studentRepository.findById(studentId).get();

        String fileName = "ходатайство_" + DateFormat.Date_Format(new Date()) + "_"
                + student.getLastName() + ".pdf";

        Petition petition = new Petition();
        petition.setName(fileName);
        petition.setStudentFaculty(student.getFaculty());
        petition.setStudentLastName(student.getLastName());
        petition.setStudent(student);

        petitionRepository.save(petition);

        return petition;
    }

    @Override
    public ResponseEntity<Void> deletePetitionById(Long id) {
        Optional<Petition> petition = petitionRepository.findById(id);
        if (petition.isPresent()) {
            petitionRepository.delete(petition.get());
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @Override
    public void downloadPetition(Long petitionId) {
        PdfGenerator pdfGenerator = new PdfGenerator();

        Petition petition = petitionRepository.findById(petitionId).get();

        String directoryName = "D:/BRSM project/документация/ходатайства";

        Path directoryPath = Paths.get(directoryName);

        PetitionTemplate petitionTemplate = new PetitionTemplate(studentRepository, eventRepository);

        Long studentId = petition.getStudent().getStudentId();
        Student student = studentRepository.findById(studentId).get();

        List<Event> petitionEvents = eventRepository.findPetitionEventsByStudentId(studentId);

        if (petitionEvents.isEmpty()) {
            return;
        }

        String petitionContent = petitionTemplate.generateContent(studentId);

        try {
            if (!Files.exists(directoryPath)) {
                Files.createDirectories(directoryPath);
            }
            String fileName = directoryName + "/ходатайство_" + DateFormat.Date_Format(Date.from(petition.getCreatedAt().toInstant())) + "_"
                    + student.getLastName() + ".pdf";

            String petitionHeader = "Проректору по\nвоспитательной работе\nКузнецову Д.Ф.\n\n\n\n";
            float[] columnWidths = {5, 2};
            pdfGenerator.createPDF(fileName, petitionHeader, petitionTemplate.generateBeforeContent(), petitionContent, columnWidths);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PdfWriter writer = new PdfWriter(outputStream);
            PdfDocument pdfDocument = new PdfDocument(writer);
            Document document = new Document(pdfDocument);
            document.add(new Paragraph(petitionContent));
            document.close();
        } catch (IOException e) {
            e.printStackTrace();
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

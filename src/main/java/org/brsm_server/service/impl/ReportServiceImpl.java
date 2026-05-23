package org.brsm_server.service.impl;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.brsm_server.entity.Report;
import org.brsm_server.entity.Student;
import org.brsm_server.exception.EntityExistsException;
import org.brsm_server.help.DateFormat;
import org.brsm_server.pdf.PdfGenerator;
import org.brsm_server.pdf.ReportTemplate;
import org.brsm_server.repository.ReportRepository;
import org.brsm_server.repository.StudentReportRepository;
import org.brsm_server.repository.StudentRepository;
import org.brsm_server.service.ReportService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.*;

@Service
@RequiredArgsConstructor
public class ReportServiceImpl implements ReportService {

    private final ReportRepository reportRepository;
    private final StudentRepository studentRepository;
    private final StudentReportRepository studentReportRepository;

    @Override
    public List<Report> getAllReports() {
        return reportRepository.findAllActive();
    }

    @Override
    @Transactional
    public Set<Report> saveReport() {

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -1);
        Date oneMonthAgoDate = calendar.getTime();
        OffsetDateTime oneMonthAgo = oneMonthAgoDate.toInstant().atZone(ZoneId.systemDefault()).toOffsetDateTime();

        List<Student> students = studentRepository.findStudentsByEventDateAfter(oneMonthAgoDate);
        List<Report> recentReports = reportRepository.findReportsByDateAfter(oneMonthAgo);

        if (!recentReports.isEmpty()) {
            return new HashSet<>();
        }

        Set<Report> returnReports = new HashSet<>();

        for (int numberOfDormitory = 1; numberOfDormitory <= 5; numberOfDormitory++) {
            Set<Student> studentsToReport = filterStudentsForDormitory(students, numberOfDormitory, oneMonthAgoDate);

            if (!studentsToReport.isEmpty()) {
                Report report = createAndSaveReport(numberOfDormitory, studentsToReport, oneMonthAgoDate);
                returnReports.add(report);
            }
        }
        return returnReports;
    }

    private Set<Student> filterStudentsForDormitory(List<Student> students, int dormNumber, Date oneMonthAgoDate) {
        Set<Student> result = new HashSet<>();
        for (Student student : students) {
            Integer optCount = studentRepository.findOptCountByStudentIdAndEventDateAfter(student.getStudentId(), oneMonthAgoDate);
            if (optCount != null && optCount > 0 && Objects.equals(student.getDormNumber(), dormNumber)) {
                result.add(student);
            }
        }
        return result;
    }

    private Report createAndSaveReport(int numberOfDormitory, Set<Student> studentsToReport, Date oneMonthAgoDate) {
        String fileName = "докладная_" + DateFormat.Date_Format(new Date()) + "_obsh" + numberOfDormitory + ".pdf";

        Report report = new Report();
        report.setName(fileName);
        report.setDormNumber(numberOfDormitory);
        report.setStudents(studentsToReport);
        reportRepository.save(report);

        for (Student student : studentsToReport) {
            Integer optCount = studentRepository.findOptCountByStudentIdAndEventDateAfter(student.getStudentId(), oneMonthAgoDate);
            studentReportRepository.addStudentToReport(student.getStudentId(), report.getDocumentId(), optCount);
        }
        return report;
    }

    @Override
    @Transactional
    public ResponseEntity<Void> deleteReportById(Long id) {
        Optional<Report> reportOptional = reportRepository.findById(id);

        if (reportOptional.isPresent()) {
            Report report = reportOptional.get();
            report.setDeleted(true);
            reportRepository.save(report);
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @Override
    public byte[] downloadReport(Long reportId) {
        PdfGenerator pdfGenerator = new PdfGenerator();
        ReportTemplate reportTemplate = new ReportTemplate();
        String directoryName = "D:/BRSM project/документация/докладные";
        Path directoryPath = Paths.get(directoryName);

        Report report = reportRepository.findById(reportId)
                .orElseThrow(() -> new EntityExistsException("Документ не найден"));

        Set<Student> students = studentReportRepository.findStudentsByReportId(reportId);

        String reportHeader = """
                Заместителю начальника студгородка \
                по информационно-воспитательной работе
                Чурбановой О.П.
                """;

        StringBuilder studentsInfo = new StringBuilder();

        for (Student student : students) {
            studentsInfo.append("студенту факультета ")
                    .append(student.getFaculty())
                    .append(" группы ")
                    .append(student.getGroupNumber())
                    .append(" ")
                    .append(student.getFullNameDative())
                    .append(", проживающему в общежитии №")
                    .append(report.getDormNumber())
                    .append(", к. ")
                    .append(student.getDormBlockNumber())
                    .append(" в количестве ")
                    .append(studentReportRepository.findOptByStudentId(student.getStudentId(), reportId))
                    .append(" часов;\n");
        }

        String reportContent = reportTemplate.generateContent(studentsInfo);
        String reportBeforeContent = reportTemplate.generateBeforeContent(Date.from(report.getCreatedAt().toInstant()));

        try {
            if (!Files.exists(directoryPath)) {
                Files.createDirectories(directoryPath);
            }

            String fileName = directoryName + "/докладная_" + DateFormat.Date_Format(Date.from(report.getCreatedAt().toInstant())) + "_obsh" + report.getDormNumber() + ".pdf";
            float[] columnWidths = {1, 1};
            pdfGenerator.createPDF(fileName, reportHeader, reportBeforeContent, reportContent, columnWidths);

            try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                PdfWriter writer = new PdfWriter(outputStream);
                PdfDocument pdfDocument = new PdfDocument(writer);
                Document document = new Document(pdfDocument)) {
                document.add(new Paragraph(reportContent));
            }

            return Files.readAllBytes(Paths.get(fileName));
        }
        catch (IOException e){
            return new byte[0];
        }
    }

}

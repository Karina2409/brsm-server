package org.brsm_system_server.service;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.brsm_system_server.entity.Student;
import org.brsm_system_server.repository.StudentRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

@Service
public class StudentImportService {

    private final StudentRepository studentRepository;

    public StudentImportService(StudentRepository studentRepository) {
        this.studentRepository = studentRepository;
    }

    public void importStudents(MultipartFile file) throws Exception {
        String filename = file.getOriginalFilename();
        if (filename.endsWith(".csv")) {
            importFromCsv(file);
        } else if (filename.endsWith(".xlsx")) {
            importFromExcel(file);
        } else {
            throw new Exception("Unsupported file format. Please upload a CSV or Excel file.");
        }
    }

    private void importFromCsv(MultipartFile file) throws IOException {
        try (InputStreamReader reader = new InputStreamReader(file.getInputStream());
             BufferedReader br = new BufferedReader(reader)) {
            Iterable<CSVRecord> records = CSVFormat.DEFAULT.withHeader().parse(br);
            List<Student> students = new ArrayList<>();
            for (CSVRecord record : records) {
                Student student = parseStudent(record);
                if (!isStudentExists(student)) {
                    students.add(student);
                }
            }
            if (!students.isEmpty()) {
                studentRepository.saveAll(students);
            }
        }
    }

    private void importFromExcel(MultipartFile file) throws IOException {
        try (InputStream inputStream = file.getInputStream()) {
            Workbook workbook = new XSSFWorkbook(inputStream);
            Sheet sheet = findSheetByName(workbook, "Список членов БРСМ");
            if (sheet != null) {
                List<Student> students = new ArrayList<>();
                for (Row row : sheet) {
                    if (row.getRowNum() == 0) continue;
                    Student student = parseStudentFromExcelRow(row);
                    if (!isStudentExists(student)) {
                        students.add(student);
                    }
                }
                if (!students.isEmpty()) {
                    studentRepository.saveAll(students);
                }
            } else {
                throw new IOException("Sheet 'Список членов БРСМ' not found.");
            }
            workbook.close();
        }
    }

    private Sheet findSheetByName(Workbook workbook, String sheetName) {
        for (int i = 0; i < workbook.getNumberOfSheets(); i++) {
            Sheet sheet = workbook.getSheetAt(i);
            if (sheet.getSheetName().equals(sheetName)) {
                return sheet;
            }
        }
        return null;
    }

    private Student parseStudent(CSVRecord record) {
        String groupNumber = record.get("GroupNumber");
        String fullName = record.get("FullName");
        String[] nameParts = fullName.split(" ");
        String lastName = nameParts[0];
        String firstName = nameParts[1];
        String middleName = (nameParts.length > 2) ? nameParts[2] : "";

        Student student = new Student();
        student.setGroupNumber(groupNumber);
        student.setLastName(lastName);
        student.setFirstName(firstName);
        student.setMiddleName(middleName);
        return student;
    }

    private Student parseStudentFromExcelRow(Row row) {
        String groupNumber = row.getCell(0).getStringCellValue();
        String fullName = row.getCell(1).getStringCellValue();
        String[] nameParts = fullName.split(" ");
        String lastName = nameParts[0];
        String firstName = nameParts[1];
        String middleName = (nameParts.length > 2) ? nameParts[2] : "";

        Student student = new Student();
        student.setGroupNumber(groupNumber);
        student.setLastName(lastName);
        student.setFirstName(firstName);
        student.setMiddleName(middleName);
        return student;
    }

    private boolean isStudentExists(Student student) {
        return studentRepository.existsByLastNameAndFirstNameAndMiddleNameAndGroupNumber(
                student.getLastName(),
                student.getFirstName(),
                student.getMiddleName(),
                student.getGroupNumber()
        );
    }
}

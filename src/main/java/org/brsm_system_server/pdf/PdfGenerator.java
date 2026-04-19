package org.brsm_system_server.pdf;

import com.itextpdf.kernel.font.PdfFont;
import com.itextpdf.kernel.font.PdfFontFactory;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.borders.Border;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;

import java.io.IOException;

public class PdfGenerator {

    private static final String FONT = "C:/Windows/Fonts/times.ttf";

    public Document createPDF(String dest, String header, String beforeContent,String content, float[] columnWidths) {
        try{
            PdfWriter writer = new PdfWriter(dest);
            PdfDocument pdf = new PdfDocument(writer);
            Document document = new Document(pdf);
            PdfFont font = PdfFontFactory.createFont(FONT, "Cp1251");

            document.add(createHeaderTable(font, header, columnWidths));

            Paragraph before = new Paragraph(beforeContent)
                    .setFont(font)
                    .setFontSize(14);
            document.add(before);

            String[] paragraphs = content.split("\n");
            for (String paragraphText : paragraphs) {

                Paragraph paragraph = new Paragraph(paragraphText)
                        .setFirstLineIndent(1.25f * 28.35f)
                        .setFont(font)
                        .setFontSize(14)
                        .setTextAlignment(TextAlignment.JUSTIFIED)
                        .setMarginBottom(0)
                        .setMarginTop(0);
                document.add(paragraph);
            }
            Paragraph str = new Paragraph("\n\n\n") ;

            document.add(str);

            document.add(createFooterTable(font));
            document.close();
            return document;
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    private Table createFooterTable(PdfFont font) {
        float[] columnWidths = {3, 1};
        Table table = new Table(UnitValue.createPercentArray(columnWidths));
        table.setWidth(UnitValue.createPercentValue(100));

        String columnName = "Секретарь ПО ОО «БРСМ»" + "\n" + "с правами РК УО «БГУИР»";
        String secretarName = "М.А. Аксёненко";

        Cell cell1 = new Cell().add(new Paragraph(columnName)
                .setFont(font)
                .setFontSize(14));
        cell1.setBorder(Border.NO_BORDER);
        table.addCell(cell1);

        Cell cell2 = new Cell().add(new Paragraph(secretarName)
                .setFont(font)
                .setFontSize(14)
                .setTextAlignment(TextAlignment.RIGHT));
        cell2.setBorder(Border.NO_BORDER);
        table.addCell(cell2);

        return table;
    }

    private Table createHeaderTable(PdfFont font, String header, float[] columnWidths){

        Table table = new Table(UnitValue.createPercentArray(columnWidths));
        table.setWidth(UnitValue.createPercentValue(100));

        String columnName = "ПО ОО «БРСМ»" + "\n" + "с правами РК УО «БГУИР»";

        Cell cell1 = new Cell().add(new Paragraph(columnName)
                .setFont(font)
                .setFontSize(14));
        cell1.setBorder(Border.NO_BORDER);
        table.addCell(cell1);

        Cell cell2 = new Cell().add(new Paragraph(header)
                .setFont(font)
                .setFontSize(14));
        cell2.setBorder(Border.NO_BORDER);
        table.addCell(cell2);

        return table;
    }

}

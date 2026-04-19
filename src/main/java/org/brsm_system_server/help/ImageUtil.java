package org.brsm_system_server.help;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class ImageUtil {
    public static byte[] imageToByteArray(String imagePath) throws IOException {
        File file = new File(imagePath);
        FileInputStream fis = new FileInputStream(file);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(buffer)) != -1) {
            bos.write(buffer, 0, bytesRead);
        }
        fis.close();
        return bos.toByteArray();
    }
}

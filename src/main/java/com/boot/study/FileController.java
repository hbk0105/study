package com.boot.study;

import com.boot.study.domain.Files;
import com.boot.study.service.FilesService;
import lombok.RequiredArgsConstructor;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.List;


@RequiredArgsConstructor
@RestController
@Controller
public class FileController {

    private Logger logger = LoggerFactory.getLogger(FileController.class);

    @Autowired
    FilesService filesService;

    @PostMapping("/fileUpload")
    public void fileUpload(HttpServletRequest request, @RequestParam("file") List<MultipartFile> files) throws Exception {

        String fileUrl = "C:/upload/gogo/";

        // 파일 업로드(여러개) 처리 부분
        for (MultipartFile file : files) {

            Files f = new Files();

            File destinationFile;
            String sourceFileName = file.getOriginalFilename();
            String sourceFileNameExtension = FilenameUtils.getExtension(sourceFileName).toLowerCase();
            String destinationFileName;

            destinationFileName = RandomStringUtils.randomAlphanumeric(32) + "." + sourceFileNameExtension;
            destinationFile = new File(fileUrl + destinationFileName);

            if(destinationFile.exists() == false){ destinationFile.mkdirs(); }

            logger.info("destinationFile :: " + destinationFile);

            file.transferTo(destinationFile);

            f.setFilename(destinationFileName);
            f.setFileOriName(sourceFileName);
            f.setFileurl(fileUrl);
            filesService.save(f);

        }

    }


    @GetMapping("/download/{fno}")
    public ResponseEntity<byte[]> fileDownload(@PathVariable("fno") int fno) throws IOException {
        Files f = filesService.getFile(fno);
        InputStream inputImage = new FileInputStream(f.getFileurl()+f.getFilename());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[512];
        int l = inputImage.read(buffer);
        while(l >= 0) {
            outputStream.write(buffer, 0, l);
            l = inputImage.read(buffer);
        }
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "image/jpg");
        return new ResponseEntity<byte[]>(outputStream.toByteArray(), headers, HttpStatus.OK);
    }


}

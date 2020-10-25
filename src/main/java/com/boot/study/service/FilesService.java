package com.boot.study.service;

import com.boot.study.domain.Files;
import com.boot.study.repository.FilesRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
public class FilesService {
    @Autowired
    FilesRepository filesRepository;

    public void save(Files files) {
        Files f = new Files();
        f.setFilename(files.getFilename());
        f.setFileOriName(files.getFileOriName());
        f.setFileurl(files.getFileurl());

        filesRepository.save(f);
    }

    @Transactional
    public Files getFile(int fno) {
        return filesRepository.findById(fno).get();
    }

}
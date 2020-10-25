package com.boot.study.repository;

import com.boot.study.domain.Files;
import org.springframework.data.jpa.repository.JpaRepository;

public interface  FilesRepository extends JpaRepository<Files, Integer> {
    Files findByFno(int fno);
}
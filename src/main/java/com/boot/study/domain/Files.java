package com.boot.study.domain;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table
public class Files {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    int fno;

    String filename;
    String fileOriName;
    String fileurl;
}
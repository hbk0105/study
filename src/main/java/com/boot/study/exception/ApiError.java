package com.boot.study.exception;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Setter
@Getter
public class ApiError {

    private int code;
    private String message;
    private Instant timestamp;

    public ApiError(int code, String message) {
        this.code = code;
        this.message = message;
        this.timestamp = Instant.now();
    }

    public ApiError(int code, String message, Instant timestamp) {
        this.code = code;
        this.message = message;
        this.timestamp = timestamp;
    }

    // Getters and setters here...
}
/*
package com.boot.study.exception;

import com.boot.study.response.ApiResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

@ControllerAdvice
public class GlobalExceptionHandler {

    // https://lottogame.tistory.com/3916

    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public ApiResponse NOT_FOUND(
            NoHandlerFoundException ex) {

        ApiResponse response = new ApiResponse(404, "Not Found");
        response.setMessage("Not Found");
        response.setResult("Fail.");

        return response;
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiResponse INTERNAL_SERVER_ERROR(
            NoHandlerFoundException ex) {

        ApiResponse response = new ApiResponse(500, "Internal Server Error");
        response.setMessage("Internal Server Error");
        response.setResult("Fail.");

        return response;
    }





    // More exception handlers here ...
}*/


package com.boot.study.exception;

import com.boot.study.HomeController;
import com.boot.study.response.ApiResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.NoHandlerFoundException;
import sun.reflect.generics.tree.VoidDescriptor;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

@RestController
@ControllerAdvice
public class GlobalExceptionHandler {

    private Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // https://lottogame.tistory.com/3916

    @ExceptionHandler(NoHandlerFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public void noHandlerFoundException(NoHandlerFoundException ex ,  HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException, ServletException {

        ApiResponse response = new ApiResponse(404, "Not Found");
        response.setMessage("Not Found");
        //response.setResult("Fail.");
        OutputStream out = httpServletResponse.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(out, response);
        out.flush();
    }

    @ExceptionHandler(RuntimeException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public void runtimeException(RuntimeException ex , HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse)   throws IOException, ServletException{

        log.info("INTERNAL_SERVER_ERROR :: !! ");

        ApiResponse response = new ApiResponse(500, "Unauthorised");
        response.setMessage("Unauthorised");
        //response.setResult("Fail");

        OutputStream out = httpServletResponse.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(out, response);
        out.flush();

    }




    // More exception handlers here ...
}

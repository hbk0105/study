package com.boot.study.exception;


import com.boot.study.response.ApiResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;

@Configuration
public class RestAccessDeniedExceptionHandler implements AccessDeniedHandler {

    private Logger log = LoggerFactory.getLogger(RestAccessDeniedExceptionHandler.class);

    @Override
    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {

        log.info("RestAccessDeniedExceptionHandler !!!!!!!!!!!!! ");

        ApiResponse response = new ApiResponse(403, "Access Denied");
        response.setMessage("Access Denied");
        //response.setResult("Fail");
        OutputStream out = httpServletResponse.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(out, response);
        out.flush();
    }
}
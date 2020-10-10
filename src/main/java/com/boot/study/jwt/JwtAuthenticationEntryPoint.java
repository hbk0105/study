package com.boot.study.jwt;

import net.minidev.json.JSONObject;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Serializable;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final long serialVersionUID = -7858869558953243875L;
/*
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        //response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");

        // status를 401 에러로 지정
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        // json 리턴 및 한글깨짐 수정.
        response.setContentType("application/json;charset=utf-8");
        JSONObject json = new JSONObject();
        String message = "잘못된 접근입니다";
        json.put("code", "9999");
        json.put("message", message);

        PrintWriter out = response.getWriter();
        out.print(json);


    }*/

    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authenticationException) throws IOException, ServletException {

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getOutputStream().println("{ \"error\": \"" + authenticationException.getMessage() + "\" }");

    }



}
package com.boot.study.filter;

import com.boot.study.service.JwtUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {

    private Logger logger = LoggerFactory.getLogger(CustomLoginSuccessHandler.class);

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Autowired
    RedisTemplate<String, Object> redisTemplate;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {


        final UserDetails userDetails = userDetailsService.loadUserByUsername("TEST");

        try {
/*
            String accessToken = JwtTokenUtil.generateAccessToken(userDetails);
            String refreshToken = JwtTokenUtil.generateRefreshToken("TEST");

            Token retok = new Token();
            retok.setUsername("TEST");
            retok.setRefreshToken(refreshToken);

            //generate Token and save in redis
            ValueOperations<String, Object> vop = redisTemplate.opsForValue();
            vop.set("TEST", retok);

            Cookie coToken = CookieUtil.createCookie(JwtTokenUtil.ACCESS_TOKEN_NAME, accessToken);

            response.addCookie(coToken);*/

        }catch (Exception e){

            e.printStackTrace();

        }





        response.sendRedirect("/");


      //  response.sendRedirect(request, response, targetUrl);



    }

}
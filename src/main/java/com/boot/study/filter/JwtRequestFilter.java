package com.boot.study.filter;


import com.boot.study.domain.Token;
import com.boot.study.jwt.JwtTokenUtil;
import com.boot.study.service.JwtUserDetailsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;


@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(JwtRequestFilter.class);

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    JwtTokenUtil jtu;

    @Autowired
    RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

  /*  public JwtRequestFilter(JwtTokenUtil jwtTokenUtil , RedisTemplate<String, Object> redisTemplate) {
        this.jwtTokenUtil = jwtTokenUtil;
        this.redisTemplate = redisTemplate;
    }*/



    public Authentication getAuthentication(String token) {
        Map<String, Object> parseInfo = jwtTokenUtil.getUserParseInfo(token);

        List<String> rs =(List)parseInfo.get("role");
        Collection<GrantedAuthority> tmp= new ArrayList<>();
        for (String a: rs) {
            tmp.add(new SimpleGrantedAuthority(a));
        }
        UserDetails userDetails = User.builder().username(String.valueOf(parseInfo.get("username"))).authorities(tmp).password("asd").build();
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        return usernamePasswordAuthenticationToken;
    }

    @Bean
    public FilterRegistrationBean JwtRequestFilterRegistration (JwtRequestFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean(filter);
        registration.setEnabled(false);
        return registration;
    }

    @SneakyThrows
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // https://do-study.tistory.com/106
        // https://velog.io/@ehdrms2034/Spring-Security-JWT-Redis%EB%A5%BC-%ED%86%B5%ED%95%9C-%ED%9A%8C%EC%9B%90%EC%9D%B8%EC%A6%9D%ED%97%88%EA%B0%80-%EA%B5%AC%ED%98%84


        String requestTokenHeader = request.getHeader("Authorization");


        // 헤더로 전달된 csrf 토큰 값
        String paramToken = request.getHeader("_csrf");

        // Double Submit Cookie
        boolean crsfdDfense = false;
        // 쿠키로 전달되 csrf 토큰 값
        String cookieToken = "";

        if(request.getCookies() != null){
            for (Cookie cookie : request.getCookies()) {
                if ("CSRF_TOKEN".equals(cookie.getName())) {
                    cookieToken = URLDecoder.decode(cookie.getValue(), "UTF-8");

                    // 재사용이 불가능하도록 쿠키 만료
                    cookie.setPath("/");
                    cookie.setValue("");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                    break;
                }
            }
        }

        // 두 값이 일치하는 지 검증
        if (cookieToken.equals(paramToken)) {
            crsfdDfense = true;
        }

        logger.info("crsfdDfense :: " + crsfdDfense);
        logger.info("paramToken :: "+ paramToken);


        String username = null;
        String jwtToken = null;


        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7).trim();

            try {

                if(jwtTokenUtil.validateToken(jwtToken)){ // 만료 체크
                    username = jwtTokenUtil.getUsername(jwtToken);
                }else{
                    // 만료

                }

            } catch (IllegalArgumentException e) {
                logger.warn("Unable to get JWT Token");
            }
            catch (ExpiredJwtException e) {
                logger.warn("Expired  JWT Token");
            }
        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }

        if (username == null) {
            logger.info("token maybe expired: username is null.");
       /* } else if (redisTemplate.opsForValue().get(username) != null) {
            logger.warn("this token already logout!");*/
        } else {


            // 토큰 값 변환 -> 리프레시 토큰 값 주기..
            java.util.Base64.Decoder decoder = java.util.Base64.getUrlDecoder();
            String[] parts = jwtToken.split("\\."); // split out the "parts" (header, payload and signature)

            String headerJson = new String(decoder.decode(parts[0]));
            String payloadJson = new String(decoder.decode(parts[1]));
            String signatureJson = new String(decoder.decode(parts[2]));

            logger.info("headerJson :: " + headerJson);
            logger.info("payloadJson :: " + payloadJson);
            logger.info("signatureJson :: " + signatureJson);
            ObjectMapper mapper = new ObjectMapper();
            Map<String, String> map = mapper.readValue(payloadJson, Map.class);


            logger.info("map :: " + map.get("sub"));

            ValueOperations<String, Object> vop2 = redisTemplate.opsForValue();
            Token result = (Token) vop2.get( map.get("sub").toString()); // 유저 이름으로 redis에서 리프레시 토큰값 추출.\

            logger.info("@#@#@ result ㅋㅋㅋㅋㅋ:: " + result);

            // 토큰 값 변환

            logger.warn("여기타니?");
            //DB access 대신에 파싱한 정보로 유저 만들기!

            //만든 authentication 객체로 매번 인증받기

            response.setHeader("username", username);

            UserDetails userDetails = jwtUserDetailsService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
                    UsernamePasswordAuthenticationToken(userDetails , null ,userDetails.getAuthorities());
            usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

            logger.info("UsernamePasswordAuthenticationToken  :: " + usernamePasswordAuthenticationToken);

            // 로그아웃 ..
            /*
            https://www.programcreek.com/java-api-examples/?api=org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler




            */


        }
        chain.doFilter(request, response);
    }
}

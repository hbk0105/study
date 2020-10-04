package com.boot.study;

import com.boot.study.domain.TokenResponse;
import com.boot.study.jwt.JwtTokenUtil;
import com.boot.study.repository.AccountRepository;
import com.boot.study.service.JwtUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

@RequiredArgsConstructor
@RestController
public class UserController {

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

   /* // 로그인
    @GetMapping("/log")
    public ResponseEntity<TokenResponse> log(@RequestBody Map<String, String> user , HttpServletRequest request , HttpServletResponse res) {

        String username = request.getParameter("username");
        final UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        return jwtTokenUtil.generateAccessToken(userDetails);
    }*/

    @GetMapping("/log")
    public ResponseEntity<TokenResponse> login( HttpServletRequest request , HttpServletResponse res) {

        String username = request.getParameter("username");
        final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
       String accessToken = jwtTokenUtil.generateAccessToken(userDetails);
        return ResponseEntity.ok().body(new TokenResponse(accessToken, "bearer"));
    }
}

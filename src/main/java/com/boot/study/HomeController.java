package com.boot.study;

import com.boot.study.domain.Account;
import com.boot.study.domain.Token;
import com.boot.study.jwt.JwtTokenUtil;
import com.boot.study.repository.AccountRepository;
import com.boot.study.service.JwtUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@RestController
@Controller
@RequestMapping(value = "/")
public class HomeController {

    private Logger logger = LoggerFactory.getLogger(HomeController.class);

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private AuthenticationManager authenticationManager; // specific for Spring Security


    @GetMapping("/hello")
    public ModelAndView welcome(OAuth2User user , Model model , HttpServletRequest request , HttpServletResponse res) throws  Exception {
        ModelAndView mav = new ModelAndView();
        mav.setViewName("home");

       // final Cookie jwtToken = CookieUtil.getCookie(request,JwtTokenUtil.ACCESS_TOKEN_NAME);

        try {

            logger.info("user :: " + user);


        }catch (Exception e){
            e.printStackTrace();
        }


        return mav;
    }


    @GetMapping(value = "/")
    public ModelAndView home(Model model , HttpServletRequest request , HttpServletResponse res) {


        ModelAndView modelAndView = new ModelAndView();

        if(request.getParameter("msg") != null){
            modelAndView.addObject("msg",request.getParameter("msg").toString());
        }

        ArrayList<HashMap<String, Object>> boardList = new ArrayList<HashMap<String, Object>>();
        Authentication auth;
        try{

            HashMap<String, Object> m  = new HashMap<>();

            m.put("username" , "user");
            m.put("password" , "1234");

            if(m != null){

                final String username = (String) m.get("username");
                logger.info("test input username: " + username);
                try {
                    // https://stackoverflow.com/questions/57020818/authenticationmanager-authenticates-gives-me-stackoverflowerror
                   /* Authentication request = new UsernamePasswordAuthenticationToken(username, m.get("password"));
                    Authentication result = authenticationManager.authenticate(request);
                    logger.info("### result :: " + result);

                    SecurityContext sc =  SecurityContextHolder.getContext();
                    sc.setAuthentication(result);
*/

                    auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, m.get("password")));

                    /*Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

                    logger.info("authentication 11 :: " + authentication);*/


                } catch (Exception e){
                    throw e;
                }

                //final UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                final UserDetails userDetails = (UserDetails) auth.getPrincipal();
                String accessToken = jwtTokenUtil.generateAccessToken(userDetails);
                String refreshToken = jwtTokenUtil.generateRefreshToken(username);

                request.setAttribute("_csrf_header", "Authorization");
                request.setAttribute("_csrf","Bearer "+accessToken);

                Token retok = new Token();
                retok.setUsername(username);
                retok.setRefreshToken(refreshToken);

                //generate Token and save in redis
                ValueOperations<String, Object> vop = redisTemplate.opsForValue();
                vop.set(username, retok);


                logger.info("generated access token: " + accessToken);
                logger.info("generated refresh token: " + refreshToken);
                Map<String, Object> map = new HashMap<>();
                map.put("accessToken", accessToken);
                map.put("refreshToken", refreshToken);

                String refreshTokenFromDb = null;
                ValueOperations<String, Object> vop2 = redisTemplate.opsForValue();
                Token result = (Token) vop2.get(username);
                refreshTokenFromDb = result.getRefreshToken();
                logger.info("rtfrom db: " + refreshTokenFromDb);
/*

                // 로그아웃 처리!
                redisTemplate.delete(username);

                redisTemplate.opsForValue().set(accessToken, true);
                redisTemplate.expire(accessToken, 10*6*1000, TimeUnit.MILLISECONDS);
                result = (Token) vop.get(username);
                logger.info("validateToken 222  :: " +  jwtTokenUtil.validateToken(accessToken));

                request.setAttribute("_csrf_header", "");
                request.setAttribute("_csrf","");

                // 로그아웃 처리!

*/


                boardList.add((HashMap<String, Object>) map);

            }





            modelAndView.setViewName("home");



            HashMap<String, Object> m1 = new HashMap<>();
            m1.put("id","m1");
            m1.put("name","이름sdsds1");

            boardList.add(m1);

            HashMap<String, Object> m2 = new HashMap<>();
            m2.put("id","m2");
            m2.put("name","2323");

            boardList.add(m2);


            modelAndView.addObject("boardList",boardList);

        }catch (Exception e){
            e.printStackTrace();
        }



        return modelAndView;
    }

    @GetMapping(path="/getusers")
    public @ResponseBody
    Iterable<Account> getAllUsers() {
        System.out.println(accountRepository.findAll());
        return accountRepository.findAll();
    }


    public void logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null){
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        SecurityContextHolder.getContext().setAuthentication(null);
    }


    // https://dkyou.tistory.com/23
    // https://cnpnote.tistory.com/entry/SPRING-Spring-Security%EB%A1%9C-%EC%9E%90%EB%8F%99%EC%9C%BC%EB%A1%9C-%EB%A1%9C%EA%B7%B8-%EC%95%84%EC%9B%83%ED%95%98%EB%8A%94-%EB%B0%A9%EB%B2%95
    @GetMapping("/tt")
    public String tt(HttpServletRequest request, HttpServletResponse response){

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        logger.info("auth ::!!11111 " + auth );
        if (auth != null){
            new SecurityContextLogoutHandler().logout(request, response, auth);
        }
        SecurityContextHolder.getContext().setAuthentication(null);

        auth = SecurityContextHolder.getContext().getAuthentication();

        logger.info("auth ::!!2222 " + auth );

        return "index";
    }

    /*
    *
    * 로그아웃 샘픔
    *https://dkyou.tistory.com/23
    * https://cnpnote.tistory.com/entry/SPRING-Spring-Security%EB%A1%9C-%EC%9E%90%EB%8F%99%EC%9C%BC%EB%A1%9C-%EB%A1%9C%EA%B7%B8-%EC%95%84%EC%9B%83%ED%95%98%EB%8A%94-%EB%B0%A9%EB%B2%95
    *
    */

    @GetMapping("/test")
    public String asdsad(HttpServletRequest request, HttpServletResponse response){
        return "index";
    }

    @GetMapping("/wow")
    public String wow(HttpServletRequest request, HttpServletResponse response){
        return "wow";
    }

    @GetMapping("/aaa")
    public ResponseEntity aaa(HttpServletRequest request, HttpServletResponse response){

        throw new RuntimeException();

       /// return "aaa";
    }


    @RequestMapping(value = "/xss" , method = RequestMethod.POST)
    public String saveCode(HttpServletRequest request) {

        Map<String , Object> param = new HashMap<>();

        param.put("name",request.getParameter("name"));

        return request.getParameter("name");
    }




    @RequestMapping("/logout")
    public ModelAndView exit(HttpServletRequest request, HttpServletResponse response) {
        // token can be revoked here if needed


        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("home");

        logger.info("@@@@ 여기 타라  !!");

        request.getSession().invalidate();
        SecurityContextHolder.getContext().setAuthentication(null);

        new SecurityContextLogoutHandler().logout(request, null, null);


        return modelAndView;
    }




}
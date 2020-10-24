package com.boot.study.filter;


import com.boot.study.domain.Token;
import com.boot.study.jwt.JwtTokenUtil;
import com.boot.study.service.JwtUserDetailsService;
import com.boot.study.util.CookieUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

import static com.boot.study.filter.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private Logger logger = LoggerFactory.getLogger(CustomLoginSuccessHandler.class);

    private HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    private RestOperations restOperations;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE =
            new ParameterizedTypeReference<Map<String, Object>>() {};

    private Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter = new OAuth2UserRequestEntityConverter();

    @Autowired
    RedisTemplate<String, Object> redisTemplate;

    @Autowired
    OAuth2AuthenticationSuccessHandler( HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository) {
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        clearAuthenticationAttributes(request, response);
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if(redirectUri.isPresent()) {
            //throw new BadRequestException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");

        }

        System.out.println("getPrincipal :: " + authentication.getPrincipal());
        System.out.println("getName :: " + authentication.getName());
        System.out.println("getAuthorities :: " + authentication.getAuthorities());

        DefaultOAuth2User user = (DefaultOAuth2User) authentication.getPrincipal();

        System.out.println("principal :: " +user.getAttribute("User Attributes"));

        String id = (String) user.getAttributes().get("id");

        List<String> li = new ArrayList<>();
        for (GrantedAuthority a: authentication.getAuthorities()) {
            li.add(a.getAuthority());
        }


        System.out.println("li :: " + li);


        /*
           1. DefaultOAuth2User 값을 이용하여 프로세스 추가 필요..

           아래 로직은 테스트 코드


        */
        /*
        final UserDetails userDetails = userDetailsService.loadUserByUsername("TEST");

        String accessToken = JwtTokenUtil.generateAccessToken(userDetails);
        String refreshToken = JwtTokenUtil.generateRefreshToken("TEST");

        Token retok = new Token();
        retok.setUsername("TEST");
        retok.setRefreshToken(refreshToken);

        //generate Token and save in redisc
        ValueOperations<String, Object> vop = redisTemplate.opsForValue();
        vop.set("TEST", retok);

        CookieUtils.addCookie(response,JwtTokenUtil.ACCESS_TOKEN_NAME, accessToken,(int) JwtTokenUtil.JWT_ACCESS_TOKEN_VALIDITY);

*/
        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        return UriComponentsBuilder.fromUriString(targetUrl)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    // 네이버는 HTTP response body에 response 안에 id 값을 포함한 유저정보를 넣어주므로 유저정보를 빼내기 위한 작업을 함
    private Map<String, Object> getUserAttributes(ResponseEntity<Map<String, Object>> response) {
        Map<String, Object> userAttributes = response.getBody();
        if(userAttributes.containsKey("response")) {
            LinkedHashMap responseData = (LinkedHashMap)userAttributes.get("response");
            userAttributes.putAll(responseData);
            userAttributes.remove("response");
        }
        return userAttributes;
    }

}

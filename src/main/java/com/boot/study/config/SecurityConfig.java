package com.boot.study.config;



import com.boot.study.exception.RestAccessDeniedExceptionHandler;
import com.boot.study.exception.RestAuthenticationExceptionHandler;
import com.boot.study.filter.*;
import com.boot.study.jwt.JwtAuthenticationEntryPoint;
import com.boot.study.service.CustomOAuth2UserService;
import com.boot.study.service.JwtUserDetailsService;
import com.boot.study.social.CustomOAuth2Provider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import static com.boot.study.social.SocialType.*;

// https://www.xspdf.com/help/50627003.html
/*@Configuration
@EnableWebSecurity
@AllArgsConstructor
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(1000)*/
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // https://jungeunlee95.github.io/java/2019/07/17/2-Spring-Security/
    // https://growing-up-constantly.tistory.com/41?category=333833


    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired private JwtAuthenticationEntryPoint unauthorizedHandler;

    @Autowired
    private OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;

    @Autowired
    private OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    public void configure(WebSecurity web) throws Exception
    {
        // static 디렉터리의 하위 파일 목록은 인증 무시 ( = 항상통과 )
        web.ignoring().antMatchers("/css/**", "/js/**", "/img/**", "/lib/**","/air-datepicker/**" ,"/assets/**" ,"/sweetalert/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {


        http
               /* // 개발 편의성을 위해 CSRF 프로텍션을 비활성화
                .csrf()
                .disable()
                // HTTP 기본 인증 비활성화
                .httpBasic()
                .disable()
                // 폼 기반 인증 비활성화
                .formLogin()
                .disable()
                // stateless한 세션 정책 설정
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()*/
                .cors().and().csrf().disable()
                .authorizeRequests()
                // 페이지 권한 설정



                .antMatchers("/test/**").hasRole("ADMIN")
                .antMatchers("/wow/**").hasRole("USER")

                .antMatchers("/fileUpload").permitAll()
                .antMatchers("/download/*").permitAll()

                .antMatchers("/aaa").permitAll()
                .antMatchers("/").permitAll()
                .antMatchers("/xss").permitAll()




               .antMatchers("/facebook").hasAuthority(FACEBOOK.getRoleType())
                .antMatchers("/google").hasAuthority(GOOGLE.getRoleType())
                .antMatchers("/kakao").hasAuthority(KAKAO.getRoleType())
                .antMatchers("/naver").hasAuthority(NAVER.getRoleType())
                .antMatchers("/github").hasAuthority(GITHUB.getRoleType())
                .antMatchers("/line").hasAuthority(LINE.getRoleType())



                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .authorizationEndpoint()
                .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                .and()
                .userInfoEndpoint().userService(new CustomOAuth2UserService())  // 네이버 USER INFO의 응답을 처리하기 위한 설정*/


/*

                .oauth2Login()
                .authorizationEndpoint()
                .baseUri("/oauth2/authorization/")
                .authorizationRequestRepository(cookieAuthorizationRequestRepository())
                .and()
                .redirectionEndpoint()
                .baseUri("/login/oauth2/callback/*")
                .and()
                .userInfoEndpoint()
                .userService(new CustomOAuth2UserService())
                .and()
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler)
*/


/*
                .and()
                .requiresChannel().anyRequest().requiresSecure()
                .and()
                .portMapper()
                .http(8080).mapsTo(8443)
                */
                .and()
                //.successHandler(customLoginSuccessHandler())
                .successHandler(oAuth2AuthenticationSuccessHandler)
                .failureHandler(oAuth2AuthenticationFailureHandler)
                //.failureUrl("/")

                .and().logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/logout")
                .logoutSuccessHandler(customLogoutSuccessHandler())
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .permitAll()


                //exceptionHandling().authenticationEntryPoint(unauthorizedHandler)
                .and().exceptionHandling().accessDeniedHandler(accessDeniedHandler()).authenticationEntryPoint(authenticationExceptionHandler())

                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and().cors().configurationSource(corsConfigurationSource())

                .and().addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class);


    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Spring Security에서 모든 인증은 AuthenticationManager를 통해 이루어지며 AuthenticationManager를 생성하기 위해서는 AuthenticationManagerBuilder를 사용
//        로그인 처리 즉, 인증을 위해서는 UserDetailService를 통해서 필요한 정보들을 가져오는데, 예제에서는 서비스 클래스(userLoginService)에서 이를 처리
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }


    // CORS 허용 적용
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.addAllowedOrigin("*");
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    CustomLogoutSuccessHandler customLogoutSuccessHandler(){
        return new CustomLogoutSuccessHandler();
    }


    @Bean
    CustomLoginSuccessHandler customLoginSuccessHandler(){
        return new CustomLoginSuccessHandler();
    }


    // 커스텀 예외처리
    @Bean
    RestAccessDeniedExceptionHandler accessDeniedHandler() {
        return new RestAccessDeniedExceptionHandler();
    }


    // 커스텀 예외처리
    @Bean
    RestAuthenticationExceptionHandler authenticationExceptionHandler() {
        return new RestAuthenticationExceptionHandler();
    }


    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(
            OAuth2ClientProperties oAuth2ClientProperties,
            @Value("${custom.oauth2.kakao.client-id}") String kakaoClientId,
            @Value("${custom.oauth2.kakao.client-secret}") String kakaoClientSecret,
            @Value("${custom.oauth2.naver.client-id}") String naverClientId,
            @Value("${custom.oauth2.naver.client-secret}") String naverClientSecret,
            @Value("${custom.oauth2.github.client-id}") String githubClientId,
            @Value("${custom.oauth2.github.client-secret}") String githubClientSecret,
            @Value("${custom.oauth2.line.client-id}") String lineClientId,
            @Value("${custom.oauth2.line.client-secret}") String lineClientSecret){
        List<ClientRegistration> registrations = oAuth2ClientProperties
                .getRegistration().keySet().stream()
                .map(client -> getRegistration(oAuth2ClientProperties, client))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        registrations.add(CustomOAuth2Provider.KAKAO.getBuilder("kakao")
                .clientId(kakaoClientId)
                .clientSecret(kakaoClientSecret)
                .jwkSetUri("temp")
                .build());

        registrations.add(CustomOAuth2Provider.NAVER.getBuilder("naver")
                .clientId(naverClientId)
                .clientSecret(naverClientSecret)
                .jwkSetUri("temp")
                .build());

        registrations.add(CustomOAuth2Provider.GITHUB.getBuilder("github")
                .clientId(githubClientId)
                .clientSecret(githubClientSecret)
                .jwkSetUri("temp")
                .build());

        registrations.add(CustomOAuth2Provider.LINE.getBuilder("line")
                .clientId(lineClientId)
                .clientSecret(lineClientSecret)
                .jwkSetUri("http://localhost:8080")
                .build());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    private ClientRegistration getRegistration(OAuth2ClientProperties clientProperties, String client) {
        if("google".equals(client)) {
            OAuth2ClientProperties.Registration registration = clientProperties.getRegistration().get("google");
            return CommonOAuth2Provider.GOOGLE.getBuilder(client)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .scope("email", "profile")
                    .build();
        }

        if("facebook".equals(client)) {
            OAuth2ClientProperties.Registration registration = clientProperties.getRegistration().get("facebook");
            return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
                    .clientId(registration.getClientId())
                    .clientSecret(registration.getClientSecret())
                    .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,link")
                    .scope("email")
                    .build();
        }

        return null;
    }


    @Bean
    public JwtDecoderFactory<ClientRegistration> idTokenecoderFactory() {
        OidcIdTokenDecoderFactory idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
        idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> MacAlgorithm.HS256);
        return idTokenDecoderFactory;
    }

    /*

    SessionCreationPolicy.STATELESS 로 세션정책을 설정한다는것은 인증 처리 관점에서 스프링 시큐리티가 더 이상 세션쿠키 방식의 인증 메카니즘으로 인증처리를 하지 않겠다는 의미로 볼 수 있습니다.

    클라이언트가 form 인증 방식으로 최초로 인증을 시도하게 되면 UsernamePasswordAuthenticationFilter 가 인증 처리를 하게 되고 인증이 성공하면  SecurityContext 에 Authentication 객체를 저장하고 인증처리는 완료됩니다.
    Authentication 객체에는 인증성공결과(User, Authorities)가 저장되어 있습니다.

    그런데 인증에 성공한 이후에 SecurityContext 객체를 세션에 저장하는 역할을 하는 SecurityContextPersistenceFilter 는  SecurityContext 객체를 세션에 저장하지 않습니다. 정확히 표현하자면 SessionCreationPolicy.STATELESS 설정으로 인해  세션 존재 여부를 떠나서 세션을 통한 인증 메커니즘 방식을 취하지 않습니다.

    그렇기 때문에 인증에 성공한 이후라도 클라이언트가 다시 어떤 자원에 접근을 시도할 경우 SecurityContextPersistenceFilter 는 세션 존재 여부를 무시하고 항상 새로운 SecurityContext 객체를 생성하기 때문에 인증성공 당시 SecurityContext 에 저장했던 Authentication 객체를 더 이상 참조 할 수 없게 되어 버립니다.

    그렇기 때문에 매번 인증을 받아야 하고 인증을 필요로 하는 상태가 됩니다.

    즉 세션방식의 인증 처리가 되지 않는 것입니다.

    이것이 인증 처리 관점에서 본 SessionCreationPolicy.STATELESS 정책이라 볼 수 있습니다.

    그런데 여기서 기억할 점은 서두에서 말씀 드린 것과 같이 SessionCreationPolicy.STATELESS 는 스프링 시큐리티가 인증 메커니즘을 진행하는 과정에서 세션을 생성하지 않는다는 것이고 혹 이미 이전에 세션이 존재한다고 하더라도 그 세션을 사용하여 세션쿠기 방식의 인증처리를 하지 않겠다는 의미이지 인증이나 인가와 직접적 연관성이 없는 다른 어떤 곳에서 보안과 관련된 특정한 처리를 해야 경우에, 그리고 만약 그 처리를 위해서 세션이 필요한 경우에는 세션을 생성 할 수 있다는 점입니다.

    한 예로 CSRF 기능입니다.

    이 기능은 인증과는 별도로 악의적인 공격자의 침입을 막기 위한 목적으로 클라이언트가  POST, PUT, DELETE 등의 HTTP METHOD 방식으로 요청할 때 반드시 csrf 토큰을 요구하게 되고 토큰이 없을 경우 서버 접근을 막고 있습니다.

    이 기능은 CsrfFilter 필터 클래스가 처리하고 있는데 처리 구문 중 아래와 같은 로직이 구현되어 있습니다.

    public void saveToken(CsrfToken token, HttpServletRequest request,
          HttpServletResponse response) {
       if (token == null) {
          HttpSession session = request.getSession(false);
          if (session != null) {
             session.removeAttribute(this.sessionAttributeName);
          }
       }
       else {
          HttpSession session = request.getSession();
          session.setAttribute(this.sessionAttributeName, token);
       }
    }
    보시면 만약 클라이언트에서 요청시 전송한 CSRF 토큰이 존재할 경우 세션을 생성하고 세션에 토큰을 저장하고 있습니다.

    HttpSession session = request.getSession(); => 세션을 무조건 생성함
    session.setAttribute(this.sessionAttributeName, token);
    이 기능은 인증/인가 처리와는 상관없이 항상 처리를 하고 있습니다.

    만약 클라이언트가 전송한 csrf 토큰이 없을 경우, 그리고 이미 존재하는 세션이 없을 경우에는 세션을 생성하지 않고 토큰을 저장하지 않습니다.

    그리고 당연한 것이지만 설정 클래스에서 CSRF 기능을 비활성화 하면 CsrfFilter 필터 클래스가 동작하지 않으므로 위 구문이 실행되지 않게 되고 세션이 생성되지 않습니다.

    즉 위 사항들을 토대로 해석해 보자면  SessionCreationPolicy.STATELESS 설정이 스프링 시큐리티가  무조건 세션을 생성하지 않는다는 의미보다는 인증 처리 관점에서 세션을 생성하지 않음과 동시에 세션을 이용한  방식으로 인증을 처리하지 않겠다는 의미로 해석할 수 있다는 점이고 인증메커니즘이 아닌 다른 특정한 곳에서 세션과 관련된 처리를 해야 하는 경우나 스프링이 아닌 다른 어플리케이션에서 세션을 사용하는 곳이 있다면 세션이 생성 될 수도 있다는 점입니다.

    그러나 세션의 존재 여부를 떠나서 SessionCreationPolicy.STATELESS 정책은 세션쿠기 방식으로 인증처리를 하지 않기 때문에 달라질 것은 특별히 없으며 대신 JWT 와 같은 토큰 개념의  방식으로 인증처리를 하면 됩니다.

    이 부분은 제가 테스트 해본 결과로 말씀 드리는 것이고 KK 님의 실행환경과 좀 차이가 날 수 있습니다.

    브라우저에서 해당 JSESSIONID 쿠기를 삭제하시고 SecurityConfig 에 http.csrf().disable() 로 하신 다음

    테스트 해 보시기 바랍니다.


    */
}
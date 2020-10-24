package com.boot.study.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private Logger logger = LoggerFactory.getLogger(CustomOAuth2UserService.class);

    private static final String MISSING_USER_INFO_URI_ERROR_CODE = "missing_user_info_uri";

    private static final String MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE = "missing_user_name_attribute";

    private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

    private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE =
            new ParameterizedTypeReference<Map<String, Object>>() {};

    private Converter<OAuth2UserRequest, RequestEntity<?>> requestEntityConverter = new OAuth2UserRequestEntityConverter();

    private RestOperations restOperations;

    public CustomOAuth2UserService() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        this.restOperations = restTemplate;
    }


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        Assert.notNull(userRequest, "userRequest cannot be null");

        if (!StringUtils.hasText(userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri())) {
            OAuth2Error oauth2Error = new OAuth2Error(
                    MISSING_USER_INFO_URI_ERROR_CODE,
                    "Missing required UserInfo Uri in UserInfoEndpoint for Client Registration: " +
                            userRequest.getClientRegistration().getRegistrationId(),
                    null
            );
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }

        String userNameAttributeName = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUserNameAttributeName();

        if (!StringUtils.hasText(userNameAttributeName)) {
            OAuth2Error oauth2Error = new OAuth2Error(
                    MISSING_USER_NAME_ATTRIBUTE_ERROR_CODE,
                    "Missing required \"user name\" attribute name in UserInfoEndpoint for Client Registration: " +
                            userRequest.getClientRegistration().getRegistrationId(),
                    null
            );
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        }

        // 소셜 정보
        logger.info("userRequest :: " + userRequest.getClientRegistration());

        ResponseEntity<Map<String, Object>> response;

        try {

            if(!"line".equals(userRequest.getClientRegistration().getRegistrationId())){
                RequestEntity<?> request = this.requestEntityConverter.convert(userRequest);
                response = this.restOperations.exchange(request, PARAMETERIZED_RESPONSE_TYPE);
            }else{

                RequestEntity<?> request = this.requestEntityConverter.convert(userRequest);
                HttpHeaders map = request.getHeaders();
                String base64Creds = map.get("Authorization").toString().replace("[","").replace("]","");
                HttpHeaders headers = new HttpHeaders();
                headers.add("Authorization", "Basic " + base64Creds);
                response = this.restOperations.exchange("https://api.line.me/v2/profile", HttpMethod.POST, request, PARAMETERIZED_RESPONSE_TYPE);
            }

        } catch (OAuth2AuthorizationException ex) {
            OAuth2Error oauth2Error = ex.getError();
            StringBuilder errorDetails = new StringBuilder();
            errorDetails.append("Error details: [");
            errorDetails.append("UserInfo Uri: ").append(
                    userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri());
            errorDetails.append(", Error Code: ").append(oauth2Error.getErrorCode());
            if (oauth2Error.getDescription() != null) {
                errorDetails.append(", Error Description: ").append(oauth2Error.getDescription());
            }
            errorDetails.append("]");
            oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the UserInfo Resource: " + errorDetails.toString(), null);

            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        } catch (RestClientException ex) {
            OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
                    "An error occurred while attempting to retrieve the UserInfo Resource: " + ex.getMessage(), null);
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
        }

        Map<String, Object> userAttributes = getUserAttributes(response);
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        authorities.add(new OAuth2UserAuthority(userAttributes));
        OAuth2AccessToken token = userRequest.getAccessToken();

        for (String authority : token.getScopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + userRequest.getClientRegistration().getRegistrationId().toUpperCase()));
        }

        logger.info("userAttributes :: " + userAttributes);
        logger.info("authorities :: " + authorities);
        logger.info("userNameAttributeName :: " + userNameAttributeName);

        //  DB에 회원정보 저장 및 수정 로직 필요

        return new DefaultOAuth2User(authorities, userAttributes, userNameAttributeName);


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

    private Set<GrantedAuthority> setGrantedAuthorities(OidcUserRequest userRequest, OidcUserInfo userInfo) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        // 이부분에서 ROLE_USER 를 추가한다.
        authorities.add(new OidcUserAuthority(userRequest.getIdToken(), userInfo));
        // SCOPE_{}는 필요없으므로 추가하지 않는다
//        OAuth2AccessToken token = userRequest.getAccessToken();
//        for (String authority : token.getScopes()) {
//            authorities.add(new SimpleGrantedAuthority("SCOPE_" + authority));
//        }

        authorities.add(new SimpleGrantedAuthority("ROLE_CUSTOMER"));

        return authorities;
    }

}

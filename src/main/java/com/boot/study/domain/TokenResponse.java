package com.boot.study.domain;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TokenResponse {

    @Getter
    @Setter
    private String accessToken;

    @Getter
    @Setter
    private String tokenType;

    public TokenResponse(String token , String type ){
        this.accessToken = token;
        this.tokenType = type;
    }




}

package com.boot.study.domain;

import lombok.Data;
import org.springframework.data.redis.core.RedisHash;

import java.io.Serializable;

@Data
@RedisHash
public class Token implements Serializable {

    private static final long serialVersionUID = -7353484588260422449L;
    private String username;
    private String refreshToken;

}

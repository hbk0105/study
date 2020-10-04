package com.boot.study.jwt;

import com.boot.study.HomeController;
import com.boot.study.domain.Token;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Component
public class JwtTokenUtil implements Serializable {

    private Logger logger = LoggerFactory.getLogger(JwtTokenUtil.class);
    private static final long serialVersionUID = -2550185165626007488L;
    public static final long JWT_ACCESS_TOKEN_VALIDITY = 10 * 60; //10분
    public static final long JWT_REFRESH_TOKEN_VALIDITY = 24 * 60 * 60 * 7; //일주일
    final static public String ACCESS_TOKEN_NAME = "accessToken";
    final static public String REFRESH_TOKEN_NAME = "refreshToken";

    private String SECRET_KEY = "YTg3OTc5MTJhOWY0ZTI2YTcwYTA1NzExZjk1MWIzOGMzNGQyYTZlNTNiYzU5YTEyZWMzNjU1ZjczYmUzYzAzZDM4YjYwODM1YWExNDllY2ZlZDllMzFlYmViOTRiOWMzM2MwOQ==";

    @Autowired
    RedisTemplate<String, Object> redisTemplate;

    //retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    //for retrieveing any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    //retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public Map<String, Object> getUserParseInfo(String token) {

        logger.info("@#@#@ token :: " + token);

        Claims parseInfo = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
        Map<String, Object> result = new HashMap<>();
        result.put("username", parseInfo.getSubject());
        result.put("role", parseInfo.get("role", List.class));
        return result;
    }


    private Key getSigningKey(String secretKey) {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Claims extractAllClaims(String token) throws ExpiredJwtException {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey(SECRET_KEY))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String getUsername(String token) throws Exception {
        return getClaimFromToken(token, Claims::getSubject);
    }

    public Boolean isTokenExpired(String token) {
        final Date expiration = extractAllClaims(token).getExpiration();
        return expiration.before(new Date());
    }

    //generate token for user
    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        List<String> li = new ArrayList<>();
        for (GrantedAuthority a: userDetails.getAuthorities()) {
            li.add(a.getAuthority());
        }
        claims.put("role",li);
        return Jwts.builder().setClaims(claims).setSubject(userDetails.getUsername()).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_ACCESS_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY).compact();
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder().setSubject(username).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_REFRESH_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY).compact();
    }
    //while creating the token -
//1. Define  claims of the token, like Issuer, Expiration, Subject, and the ID
//2. Sign the JWT using the HS512 algorithm and secret key.
//3. According to JWS Compact Serialization(https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-41#section-3.1)
//   compaction of the JWT to a URL-safe string
    /*
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY * 1000))
                .signWith(SignatureAlgorithm.HS512, secret).compact();
    }

     */
    //validate token
   /* public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    */


    public boolean validateToken(String accessToken ) {
        try {
           // Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(authToken); return true;

            Map<String, Object> map =  getUserParseInfo(accessToken);
            final String username = (String) map.get("username");

            ValueOperations<String, Object> vop = redisTemplate.opsForValue();
            Token result = (Token) vop.get(username);

            if( result != null &&  result.getUsername().equals(username)) return true;

        } catch (SignatureException ex) {
            logger.error("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        } return false;
    }



}

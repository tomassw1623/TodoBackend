package com.todobackend.todo.security;

import com.todobackend.todo.model.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.log4j.Log4j2;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Log4j2
@Service
public class TokenProvider {

    private static final String SECRET_KEY = "FlRpX30pMqDbiAkmlfArbrmVkDD4RqISskGZmBFax5oGVxzXXWUzTR5JyskiHMIV9M1Oicegkpi46AdvrcX1E6CmTUBc6IFbTPiD";


    public String create(UserEntity userEntity) {  //토큰 생성...
        // 기한 - 지금부터 1일까지 설정.
        Date expiryDate = Date.from(
                Instant.now()
                        .plus(1, ChronoUnit.DAYS));
        /*
        { // header
           "typ" : "JWT", -- 늘 같아요...
           "alg" : "HS512"
        }.
        {
            // payload
            "sub":"4028890 ~~~~ ",  //대상...
            "iss":"todo app",       //발급자
            "iat": 1595733657,      //생성시점
            "exp": 1596597657       //만료시점
        }.
        // SECRET_KEY를 이용해서 서명한 부분..
        ..... ~~~~
         */
        // JWT Token 생성
        return Jwts.builder()
                // header에 들어갈 내용 및 서명을 하기 위한 SECRET_KEY
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                // payLoad에 들어갈 내용
                .setSubject(userEntity.getId()) //sub...
                .setIssuer("todo app")          //iss...
                .setIssuedAt(new Date())        //iat...
                .setExpiration(expiryDate)      //exp...
                .compact();
    }

    public String validateAndGetUserID(String token){ //토큰 검증 및 UserId 얻기..
        // parseClaimsJws 메서드가 Base64로 디코딩 및 파싱
        // 즉, 헤더와 페이로드를 setSigningKey로 넘어온 시크릿을 이용해서 서명 후,
        // token의 서버명과 비교. 위조되지 않았다면 페이로드(Claims)리턴, 위조라면 예외를 날림
        // 그중에 userId가 필요하므로 getBody를 불러 줍니다.
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build().parseClaimsJws(token).getBody();

        return claims.getSubject();   // UserEntity의 id값을 반환...
    }

    public String create(final Authentication authentication){
        OAuth2User userPrincipal = (OAuth2User) authentication.getPrincipal();
        Date expiryDate = Date.from(
                Instant.now()
                        .plus(1, ChronoUnit.DAYS));

        return Jwts.builder()
                .setSubject(userPrincipal.getName()) //userEntity.getId()
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }
}

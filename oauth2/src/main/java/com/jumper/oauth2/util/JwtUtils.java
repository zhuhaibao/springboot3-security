package com.jumper.oauth2.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
@Slf4j
public class JwtUtils {
    public static void main(String[] args) {
        JwtUtils jwtUtils = new JwtUtils();
        String sign = jwtUtils.genSign("user");
        System.out.println(sign);
        System.out.println(jwtUtils.extractUsernameFromSign(sign));
    }

    public String genSign(String username) {
        return Jwts.builder().signWith(getKey()).setSubject(username).compact();
    }

    public String extractUsernameFromSign(String sign) {
        return Jwts.parserBuilder().setSigningKey(getKey()).build().parseClaimsJws(sign).getBody().getSubject();
    }

    public Key getKey() {
        String secret = "3C1275309CD562870F5592B00BB356A43C1275309CD562870F5592B00BB356A43C";
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public boolean validateSign(String sign) {
        try {
            Jwts.parserBuilder().setSigningKey(getKey()).build().parseClaimsJws(sign);
            return true;
        } catch (Exception e) {
            log.error("invalided sign :{}", sign);
        }
        return false;
    }
}

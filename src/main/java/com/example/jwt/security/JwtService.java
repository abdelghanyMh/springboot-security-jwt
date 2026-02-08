package com.example.jwt.security;

import com.example.jwt.user.User;
// 🔐 JWT library - Claims class for token payload data
import io.jsonwebtoken.Claims;
// ⚠️ JWT library - Exception for invalid/expired tokens
import io.jsonwebtoken.JwtException;
// 🎫 JWT library - Jwts builder for creating and parsing tokens
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

// ⏰ Java Date API - for token timestamps
import java.util.Date;

@Service
@AllArgsConstructor
public class JwtService {
  // ⚙️ JWT configuration - contains secret key and expiration times
  private final JwtConfig jwtConfig;

  // 🎫 Generate short-lived access token (15 minutes) for API requests
  public Jwt genereateAccessToken(User user) {
    // 🔧 Reuse token generation logic with access token expiration time
    return genereateToken(user, jwtConfig.getAccessTokenExpiration());
  }

  // 🔄 Generate long-lived refresh token (7 days) for getting new access tokens
  public Jwt generateRefeshToken(User user) {
    // 🔧 Reuse token generation logic with refresh token expiration time
    return genereateToken(user, jwtConfig.getRefreshTokenExpiration());
  }

  // 🔨 Core token generation logic - creates JWT with user data and expiration
  private Jwt genereateToken(User user, int tokenExpiration) {
    // 📋 Build JWT claims (payload) with user information
    var claims =
        Jwts.claims()
            .subject(user.getId().toString()) // 🆔 User ID as subject
            .add("email", user.getEmail()) // 📧 User email claim
            .add("name", user.getName()) // 📛 User name claim
            .add("role", user.getRole()) // 👑 User role/permissions claim
            .issuedAt(new Date()) // 📅 Token creation timestamp
            .expiration(new Date(System.currentTimeMillis() + (long) 1000 * tokenExpiration)) // ⏰ Expiration time (FIXED: was multiplication, should be addition!)
            .build();

    // 🎫 Create Jwt object with claims and secret key for signing
    return new Jwt(claims, jwtConfig.getSecretKey());
  }

  // 🔍 Parse and validate JWT token string back to Jwt object
  public Jwt parseToken(String token) {
    try {
      // 📋 Extract claims from token string
      var claims = getClaims(token);
      // 🎫 Create Jwt object with validated claims and secret key
      return new Jwt(claims, jwtConfig.getSecretKey());
    } catch (JwtException e) {
      // ❌ Return null if token is invalid/expired (security measure!)
      return null;
    }
  }

  // 🔧 Extract and validate claims from JWT token string
  private Claims getClaims(String token) {
    // 🔨 Parse JWT token, verify signature with secret key, and extract payload
    return Jwts.parser()
        .verifyWith(jwtConfig.getSecretKey()) // 🔐 Verify token signature with secret key
        .build() // 🏗️ Build the parser
        .parseSignedClaims(token) // 🎫 Parse the signed token
        .getPayload(); // 📋 Extract the claims payload
  }
}

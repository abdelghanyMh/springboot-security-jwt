 package com.example.jwt.security;

// 👤 Import user Role enum for authorization levels
import com.example.jwt.user.Role;
// 🔐 JWT library - provides Claims class for token payload data
import io.jsonwebtoken.Claims;
// 🎫 JWT library - Jwts builder for creating and parsing tokens
import io.jsonwebtoken.Jwts;
// 🏗️ Lombok annotation - auto-generates constructor with all required fields
import lombok.AllArgsConstructor;

// 🛡️ Java crypto API - SecretKey for signing/verifying JWT tokens
import javax.crypto.SecretKey;
// ⏰ Java Date API - for token expiration checking
import java.util.Date;

// 🤖 @AllArgsConstructor - Lombok magic: creates constructor with all fields (claims, secretKey)
@AllArgsConstructor
public class Jwt {
    // 📋 Claims - JWT payload containing user data (id, role, expiration, etc.)
    private final Claims claims;
    // 🔑 SecretKey - cryptographic key used to sign/verify this JWT token
    private final SecretKey secretKey;

    // ⏰ Check if token has expired (past its "best before" date!)
    public boolean isExpired(){
    // 📅 Compare token expiration time with current time
    return claims.getExpiration().before(new Date());
    }
    
    // 🆔 Extract user ID from JWT token (who owns this token?)
    public long getUserId(){
        // 🎯 Subject field typically contains user ID in JWT standards
        return  Long.valueOf(claims.getSubject());
    }

    // 👑 Get user's role/permissions from token (what can they do?)
    public Role getRole(){
        // 🏷️ Custom claim "role" stored as String, converted back to Role enum
        return Role.valueOf(claims.get("role",String.class));
    }

    // 🎨 Convert JWT object back to compact string format
    public String toString() {
        // 🔨 Rebuild JWT token using claims and sign it with secret key
        return Jwts.builder().claims(claims).signWith(secretKey).compact();
    }
}

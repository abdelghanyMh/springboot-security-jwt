package com.example.jwt.security;

import lombok.Data;
// ⚙️ Spring Boot annotation - binds external properties to this configuration class
import org.springframework.boot.context.properties.ConfigurationProperties;
// 🌱 Spring annotation - marks this class as a configuration bean for Spring's IoC container
import org.springframework.context.annotation.Configuration;
// 🔐 JWT library - provides cryptographic key generation for secure token signing
import io.jsonwebtoken.security.Keys;

// 🛡️ Java crypto API - provides SecretKey interface for cryptographic operations
import javax.crypto.SecretKey;

// 🌱 @Configuration - Tells Spring "Hey! This class contains configuration beans!"
@Configuration
// 📝 @ConfigurationProperties - Maps application.yml properties starting with "spring.jwt" to fields below
@ConfigurationProperties(prefix = "spring.jwt")
@Data
public class JwtConfig {
    // 🔑 The secret key used to sign JWT tokens - keep this super secret! 🤫
    private String secret;
    // ⏰ Access token lifetime in seconds - short-lived for security (e.g., 15 minutes)
    private int accessTokenExpiration;
    // 🔄 Refresh token lifetime in seconds - longer-lived for getting new access tokens (e.g., 7 days)
    private int refreshTokenExpiration;
    
    // 🔧 Method to convert string secret to proper cryptographic SecretKey object
    public SecretKey getSecretKey(){
        // 🗝️ HMAC-SHA algorithm creates a secure key from your secret string for JWT signing
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

}

// 📦 Package declaration - authentication and authorization services
package com.example.jwt.security;

// 👤 User entity - represents user data in the system
import com.example.jwt.user.User;
// 🗄️ UserRepository - database operations for User entities
import com.example.jwt.user.UserRepository;
// 🤖 Lombok - auto-generates constructor with all fields
import lombok.AllArgsConstructor;
// 🔐 Spring Security - manages authentication process
import org.springframework.security.authentication.AuthenticationManager;
// ❌ Spring Security - exception for invalid credentials
import org.springframework.security.authentication.BadCredentialsException;
// 🔐 Spring Security - token for username/password authentication
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// 🛡️ Spring Security - holds authentication information for current request
import org.springframework.security.core.context.SecurityContextHolder;
// 🌱 Spring annotation - marks this class as a service bean for business logic
import org.springframework.stereotype.Service;

// 🤖 @AllArgsConstructor - Lombok magic: creates constructor with all fields
// 🌱 @Service - Tells Spring "Hey! This class contains authentication business logic!"
@AllArgsConstructor
@Service
public class AuthService {
    // 🔐 AuthenticationManager - Spring Security's main authentication component
    private final AuthenticationManager authenticationManager;
    // 🗄️ UserRepository - database access for user operations
    private final UserRepository userRepository;
    // 🎫 JwtService - handles JWT token generation and validation
    private final JwtService jwtService;


    // 👤 Get currently authenticated user from security context
    public User getCurrentUser(){
        // 🛡️ Get authentication object from Spring Security context
        var authentification = SecurityContextHolder.getContext().getAuthentication();
        // 🆔 Extract user ID from authentication principal
        var userId = (long) authentification.getPrincipal();
        // 🔍 Find user in database by ID (returns null if not found)
        return  userRepository.findById(userId).orElse(null);
    }
    
    // 🔐 Authenticate user and return JWT tokens
    public  LoginResponse login(LoginRequest request ){
        // 🔐 Authenticate user credentials with Spring Security
        authenticationManager.authenticate(
                // 🔐 Create authentication token with email and password
                new UsernamePasswordAuthenticationToken(
                        // 📧 User email as username
                        request.getEmail(),
                        // 🔑 User password for verification
                        request.getPassword()
                )
        );
        // 🔍 Find user in database by email (throws exception if not found)
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        // 🎫 Generate short-lived access token for API requests
        var accessToken = jwtService.generateAccessToken(user);
        // 🔄 Generate long-lived refresh token for getting new access tokens
        var refreshToken = jwtService.generateRefeshToken(user);

        // 📬 Return both tokens to client
        return new LoginResponse(accessToken,refreshToken);


    }
    
    // 🔄 Generate new access token using valid refresh token
    public Jwt refreshAccessToken(String refreshToken) {
        // 🔍 Parse and validate the refresh token
        var jwt = jwtService.parseToken(refreshToken);
        // ❌ Check if refresh token is invalid or expired
        if (jwt == null || jwt.isExpired()) {
            // 🚫 Throw exception for invalid refresh token
            throw new BadCredentialsException("Invalid refresh token");
        }

        // 🔍 Find user in database by ID from refresh token
        var user = userRepository.findById(jwt.getUserId()).orElseThrow();
        // 🎫 Generate new access token for the user
        return jwtService.generateAccessToken(user);
    }
}


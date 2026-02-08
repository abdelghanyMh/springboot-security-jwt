package com.example.jwt.security;

import com.example.jwt.user.UserDto;
import com.example.jwt.user.UserMapper;
// 🍪 HTTP Cookie - for storing refresh token securely
import jakarta.servlet.http.Cookie;
// 📬 HTTP response - for adding cookies and sending responses
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
// ❌ Spring Security - exception for invalid credentials
import org.springframework.security.authentication.BadCredentialsException;
// 🌐 Spring Web MVC - annotations for REST API endpoints
import org.springframework.web.bind.annotation.*;

@AllArgsConstructor
@RestController
@RequestMapping("/auth")
public class AuthController {
    // ⚙️ JWT configuration - contains token expiration settings
    private final JwtConfig jwtConfig;
    // 🔄 User mapper - converts User entities to DTOs for API responses
    private final UserMapper userMapper;
    // 🔐 Authentication service - handles login and token operations
    private final AuthService authService;

    // 🔐 POST /auth/login - Authenticate user and return JWT tokens
    @PostMapping("/login")
    public JwtResponse login(
        // ✅ @Valid - Validates request body before processing
        // 📦 @RequestBody - Converts JSON request body to LoginRequest object
        @Valid @RequestBody LoginRequest request,
        // 📬 HTTP response - for adding refresh token cookie
        HttpServletResponse response) {

        // 🔐 Authenticate user credentials and get JWT tokens
        var loginResult = authService.login(request);

        // 🍪 Convert refresh token to string for cookie
        var refreshToken = loginResult.getRefreshToken().toString();
        // 🍪 Create secure HTTP-only cookie for refresh token
        var cookie = new Cookie("refreshToken", refreshToken);
        // 🔒 HttpOnly - prevents JavaScript access (security!)
        cookie.setHttpOnly(true);
        // 🛤️ Path - cookie only sent to refresh endpoint
        cookie.setPath("/auth/refresh");
        // ⏰ Max age - cookie expires when refresh token expires
        cookie.setMaxAge(jwtConfig.getRefreshTokenExpiration());
        // 🔒 Secure - only sent over HTTPS (production security!)
        cookie.setSecure(true);
        // 🍪 Add cookie to HTTP response
        response.addCookie(cookie);

        // 📬 Return access token in response body
        return new JwtResponse(loginResult.getAccessToken().toString());
    }

    // 🔄 POST /auth/refresh - Generate new access token using refresh token
    @PostMapping("/refresh")
    // 🍪 @CookieValue - Extracts refresh token from HTTP cookie
    public JwtResponse refresh(@CookieValue(value = "refreshToken") String refreshToken) {
        // 🔄 Generate new access token using refresh token
        var accessToken = authService.refreshAccessToken(refreshToken);
        // 📬 Return new access token in response body
        return new JwtResponse(accessToken.toString());
    }

    // 👤 GET /auth/me - Get current authenticated user information
    @GetMapping("/me")
    public ResponseEntity<UserDto> me() {
        // 👤 Get currently authenticated user from security context
        var user = authService.getCurrentUser();
        // ❌ Check if user is not found
        if (user == null) {
            // 📬 Return 404 Not Found if user doesn't exist
            return ResponseEntity.notFound().build();
        }

        // 🔄 Convert User entity to UserDto for API response
        var userDto = userMapper.toDto(user);
        // 📬 Return 200 OK with user data
        return ResponseEntity.ok(userDto);
    }

    // 🚨 Exception handler - handles invalid credentials during login/refresh
    @ExceptionHandler(BadCredentialsException.class)
    // 📬 Returns 401 Unauthorized with empty body
    public ResponseEntity<Void> handleBadCredentialsException() {
        // 📄 Return 401 status (invalid email/password or refresh token)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}

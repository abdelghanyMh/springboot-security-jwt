package com.example.jwt.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
// 🌐 HTTP request - represents incoming HTTP request
import jakarta.servlet.http.HttpServletRequest;
// 📬 HTTP response - represents outgoing HTTP response
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
// 🔐 Spring Security - authentication token for username/password
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// 👑 Spring Security - represents user permission/role
import org.springframework.security.core.authority.SimpleGrantedAuthority;
// 🛡️ Spring Security - holds authentication information for current request
import org.springframework.security.core.context.SecurityContextHolder;
// 🌐 Spring Security - adds web-specific details to authentication
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// 🔍 Spring Security - base class for filters that run once per request
import org.springframework.web.filter.OncePerRequestFilter;

// 💾 IOException - exception for I/O operations
import java.io.IOException;
// 📋 Java List - collection for user authorities/roles
import java.util.List;

@AllArgsConstructor
// 🔍 JWT Authentication Filter - extracts and validates JWT tokens from HTTP requests
// Extends OncePerRequestFilter - ensures filter runs exactly once per request
public class JwtAuthentificationFilter extends OncePerRequestFilter {
  // 🔧 JWT service - handles token parsing and validation
  private final JwtService jwtService;

  // 🔍 Core filter method - processes every HTTP request for JWT authentication
  @Override
  protected void doFilterInternal(
      // 🌐 HTTP request - incoming request from client
      HttpServletRequest request, 
      // 📬 HTTP response - response to be sent to client
      HttpServletResponse response, 
      // 🔗 FilterChain - chain of filters to continue processing
      FilterChain filterChain)
      // ⚠️ Exceptions that can occur during filter processing
      throws ServletException, IOException {
    // 📋 Extract Authorization header from HTTP request
    var authHeader = request.getHeader("Authorization");

    // ❌ Check if header is missing or doesn't start with "Bearer "
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      // 🔗 Continue to next filter (no JWT authentication)
      filterChain.doFilter(request, response);
      return;
    }
    // 🎫 Extract JWT token by removing "Bearer " prefix
    var token = authHeader.replace("Bearer ", "");
    // 🔍 Parse and validate the JWT token
    var jwt = jwtService.parseToken(token);

    // ❌ Check if token is invalid or expired
    if (jwt == null || jwt.isExpired()) {
      // 🔗 Continue to next filter (authentication failed)
      filterChain.doFilter(request, response);
      return;
    }

    // 🔐 Create Spring Security authentication object
    var authentication =
        new UsernamePasswordAuthenticationToken(
            // 🆔 User ID from JWT token (principal)
            jwt.getUserId(), 
            // 🔑 No credentials needed for JWT (null)
            null, 
            // 👑 User roles/permissions from JWT token
            List.of(new SimpleGrantedAuthority("ROLE_" + jwt.getRole())));
    // 🌐 Add web-specific details (IP address, session ID) to authentication
    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

    // 🛡️ Set authentication in Spring Security context for this request
    SecurityContextHolder.getContext().setAuthentication(authentication);

    // 🔗 Continue to next filter in the chain (now authenticated!)
    filterChain.doFilter(request, response);
  }
}

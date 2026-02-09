// 📦 Package declaration - Spring Security configuration
package com.example.jwt.security;

// 🤖 Lombok - auto-generates constructor with all fields
import com.example.jwt.common.SecurityRules;
import lombok.AllArgsConstructor;
// 🌱 Spring annotation - registers bean in Spring container
import org.springframework.context.annotation.Bean;
// ⚙️ Spring annotation - marks this class as configuration
import org.springframework.context.annotation.Configuration;
// 🌐 Spring Web - HTTP status codes
import org.springframework.http.HttpStatus;
// 🔐 Spring Security - manages authentication process
import org.springframework.security.authentication.AuthenticationManager;
// 🔐 Spring Security - provides authentication mechanisms
import org.springframework.security.authentication.AuthenticationProvider;
// 🔐 Spring Security - DAO-based authentication provider
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
// 🛡️ Spring Security - authentication configuration
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// 🛡️ Spring Security - HTTP security configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// 🛡️ Spring Security - enables web security
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// 🛡️ Spring Security - disables specific security features
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// 🛡️ Spring Security - session management policies
import org.springframework.security.config.http.SessionCreationPolicy;
// 👤 Spring Security - user details service for authentication
import org.springframework.security.core.userdetails.UserDetailsService;
// 🔐 Spring Security - BCrypt password encoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// 🔐 Spring Security - password encoding interface
import org.springframework.security.crypto.password.PasswordEncoder;
// 🛡️ Spring Security - security filter chain
import org.springframework.security.web.SecurityFilterChain;
// 🛡️ Spring Security - HTTP status entry point for unauthenticated requests
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
// 🛡️ Spring Security - username/password authentication filter
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 📋 Java List - collection for security rules
import java.util.List;

// ⚙️ @Configuration - Tells Spring "Hey! This class contains security configuration!"
// 🛡️ @EnableWebSecurity - Enables Spring Security web security features
// 🤖 @AllArgsConstructor - Lombok magic: creates constructor with all fields
@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {
    // 👤 UserDetailsService - loads user data for authentication
    private final UserDetailsService userDetailsService;
    // 🔍 JWT authentication filter - validates JWT tokens on each request
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    // 📋 List of security rules - allows modular security configuration
    private final List<SecurityRules> featureSecurityRules;

    // 🔐 Password encoder bean - encrypts passwords using BCrypt
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 🔒 BCrypt - strong password hashing algorithm (salts automatically!)
        return new BCryptPasswordEncoder();
    }

    // 🔐 Authentication provider bean - handles username/password authentication
    @Bean
    public AuthenticationProvider authenticationProvider() {
        // 🔧 Create DAO-based authentication provider
        var provider = new DaoAuthenticationProvider();
        // 🔒 Set password encoder for secure password verification
        provider.setPasswordEncoder(passwordEncoder());
        // 👤 Set user details service for loading user data
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    // 🔐 Authentication manager bean - coordinates authentication providers
    @Bean
    public AuthenticationManager authenticationManager(
            // ⚙️ Authentication configuration from Spring
            AuthenticationConfiguration config) throws Exception {
        // 🔧 Get authentication manager from configuration
        return config.getAuthenticationManager();
    }

    // 🛡️ Security filter chain bean - configures HTTP security rules
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 🚫 Stateless session - JWT doesn't need server-side sessions
            .sessionManagement(c ->
                    c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // 🚫 Disable CSRF - not needed for JWT APIs (stateless)
            .csrf(AbstractHttpConfigurer::disable)
            // 🔐 Configure URL access rules
            .authorizeHttpRequests(c -> {
                    // 📋 Apply all security rules from different modules
                    featureSecurityRules.forEach(r -> r.configure(c));
                    // 🔒 All other requests require authentication
                    c.anyRequest().authenticated();
                }
            )
            // 🔍 Add JWT filter before username/password filter
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
            // 🚨 Configure exception handling
            .exceptionHandling(c -> {
                // 🚪 Entry point for unauthenticated requests
                c.authenticationEntryPoint(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));
                // 🚫 Handler for access denied (authenticated but insufficient permissions)
                c.accessDeniedHandler(((request, response, accessDeniedException) ->
                    // 📄 Return 403 Forbidden status
                    response.setStatus(HttpStatus.FORBIDDEN.value())));
            });

        // 🔨 Build and return the security filter chain
        return http.build();
    }
}

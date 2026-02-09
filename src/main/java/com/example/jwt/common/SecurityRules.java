// 📦 Package declaration - common security utilities and interfaces
package com.example.jwt.common;

// 🛡️ Spring Security - HTTP security configuration builder
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// 📋 Spring Security - authorization request matcher registry for URL access rules
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;

// 🎯 SecurityRules interface - defines contract for configuring URL access patterns
// Allows different modules to define their own security rules
public interface SecurityRules {
    // 🔧 Configure method - defines URL access patterns and permissions
    // registry - used to specify which URLs need authentication, roles, or are public
    void configure(AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry registry);
}

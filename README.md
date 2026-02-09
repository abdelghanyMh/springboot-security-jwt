# 🔐 Spring Boot JWT Authentication - Step-by-Step Guide

> **Learn JWT authentication from zero!** This guide helps you build JWT auth in any Spring Boot project.

---

## 📚 Table of Contents

1. [What is JWT?](#-what-is-jwt)
2. [Understanding Auth & Spring Security](#-understanding-authentication--spring-security) 🆕
3. [Project Setup](#-step-1-project-setup)
4. [Add Dependencies](#-step-2-add-dependencies)
5. [Database Setup](#-step-3-database-setup)
6. [Create User Entity](#-step-4-create-user-entity)
7. [JWT Configuration](#-step-5-jwt-configuration)
8. [JWT Service](#-step-6-jwt-service)
9. [JWT Filter](#-step-7-jwt-authentication-filter)
10. [Security Config](#-step-8-security-configuration)
11. [Auth Controller](#-step-9-auth-controller)
12. [Test the API](#-step-10-test-the-api)


---

## 🤔 What is JWT?

**JWT = JSON Web Token** 🎫

Think of JWT like a **concert ticket**:

- 🎟️ You show your ID (login) → get a ticket (token)
- 🚪 At the door, you show your ticket → they let you in
- ⏰ Ticket expires after the concert → you need a new one

**JWT has 3 parts** (separated by dots):

```
xxxxx.yyyyy.zzzzz
  ↓      ↓      ↓
Header.Payload.Signature
```

---

## 📖 Understanding Authentication & Spring Security

> 🎓 **This section explains the "why" before the "how"** - based on Code with Mosh concepts.

### 🔐 Authentication Methods: Session vs Token

We have **two main ways** to authenticate users:

| Method | How it works | Best for |
|--------|--------------|----------|
| 🍪 **Session-based** | Server stores session data | Traditional web apps |
| 🎫 **Token-based** | Stateless JWTs | REST APIs ✅ |

```mermaid
flowchart LR
    subgraph Session["🍪 Session-Based"]
        A1[User Login] --> A2[Server creates session]
        A2 --> A3[Session stored in memory DB]
        A3 --> A4[Session ID sent to browser]
    end
    
    subgraph Token["🎫 Token-Based"]
        B1[User Login] --> B2[Server creates JWT]
        B2 --> B3[Nothing stored on server!]
        B3 --> B4[JWT sent to client]
    end
```

> 💡 **Why JWT for APIs?** No need to store anything on the server = easy to scale!

---

### 🔑 Password Security with Spring

Spring Security uses `PasswordEncoder` to hash passwords:

```java
// ❌ NEVER store plain passwords!
password = "secret123"

// ✅ Store hashed passwords
password = "$2a$10$N9qo8uLOickgx2ZMRZoMye..."  // BCrypt hash
```

**How authentication works:**

```mermaid
sequenceDiagram
    participant U as 👤 User
    participant C as 🌐 Controller
    participant AM as 🔐 AuthenticationManager
    participant AP as 🔧 AuthenticationProvider
    participant UDS as 👥 UserDetailsService
    participant DB as 💾 Database

    U->>C: POST /auth/login (email, password)
    C->>AM: authenticate()
    AM->>AP: authenticate()
    AP->>UDS: loadUserByUsername(email)
    UDS->>DB: findByEmail(email)
    DB-->>UDS: User data
    UDS-->>AP: UserDetails
    AP->>AP: Compare password hashes
    AP-->>AM: Authentication result
    AM-->>C: Success/Failure
    C-->>U: JWT tokens / 401 Error
```

---

### 🏗️ Spring Security Architecture

```mermaid
classDiagram
    class AuthenticationManager {
        <<interface>>
        +authenticate()
    }
    
    class AuthenticationProvider {
        <<interface>>
        +authenticate()
    }
    
    class DaoAuthenticationProvider {
        -userDetailsService
        -passwordEncoder
        +authenticate()
    }
    
    class UserDetailsService {
        <<interface>>
        +loadUserByUsername()
    }
    
    class PasswordEncoder {
        <<interface>>
        +encode()
        +matches()
    }
    
    AuthenticationManager ..> AuthenticationProvider : delegates to
    AuthenticationProvider <|-- DaoAuthenticationProvider : implements
    DaoAuthenticationProvider --> UserDetailsService : uses
    DaoAuthenticationProvider --> PasswordEncoder : uses
```

**Key components:**

| Component | Job |
|-----------|-----|
| `AuthenticationManager` | 🎯 Main entry point for authentication |
| `AuthenticationProvider` | 🔧 Does the actual authentication work |
| `DaoAuthenticationProvider` | 📋 Checks username/password against database |
| `UserDetailsService` | 👤 Loads user data from database |
| `PasswordEncoder` | 🔒 Hashes and verifies passwords |

---

### 🎫 JWT Deep Dive

A JWT is a **compact, URL-safe string** with 3 parts:

```
eyJhbGciOiJIUzM4NCJ9.eyJzdWIiOiIxIiwiZW1haWwiOiJqb2huQHRlc3QuY29tIn0.abc123signature
└──────── Header ────────┘└────────────── Payload ──────────────────────────┘└─ Signature ─┘
```

```mermaid
flowchart TB
    subgraph JWT["🎫 JWT Token Structure"]
        H["📋 Header<br/>Algorithm + Type"]
        P["📦 Payload<br/>User data (claims)"]
        S["✍️ Signature<br/>Cryptographic hash"]
    end
    
    H --> |"."| P
    P --> |"."| S
    
    subgraph Header_Content["Header Content"]
        H1["alg: HS384"]
        H2["typ: JWT"]
    end
    
    subgraph Payload_Content["Payload Content (Claims)"]
        P1["sub: 1 (user ID)"]
        P2["email: john@test.com"]
        P3["role: USER"]
        P4["exp: 1699999999"]
    end
    
    H -.-> Header_Content
    P -.-> Payload_Content
```

**JWT Parts Explained:**

| Part | What's inside | Purpose |
|------|--------------|---------|
| 🔷 **Header** | `alg: HS384`, `typ: JWT` | Tells how token was signed |
| 🟢 **Payload** | User ID, email, role, expiration | Carries the actual data |
| 🔴 **Signature** | HMAC hash of header + payload | Prevents tampering! |

---

### 🎭 Access Token vs Refresh Token

We use **TWO types of tokens** for security:

```mermaid
flowchart TB
    subgraph Access["🎫 Access Token"]
        A1["⏱️ Short-lived: 15 minutes"]
        A2["📡 Sent on every API request"]
        A3["💾 Stored in memory or localStorage"]
        A4["⚠️ If stolen: limited damage"]
    end
    
    subgraph Refresh["🔄 Refresh Token"]
        R1["⏱️ Long-lived: 7 days"]
        R2["🔄 Only used to get new access token"]
        R3["🍪 Stored in HttpOnly cookie"]
        R4["🔒 Not accessible by JavaScript"]
    end
    
    Login["🔐 Login"] --> Access
    Login --> Refresh
    
    Refresh --> |"When access token expires"| NewAccess["🆕 New Access Token"]
```

**Token Comparison:**

| Feature | 🎫 Access Token | 🔄 Refresh Token |
|---------|-----------------|------------------|
| **Purpose** | Access API endpoints | Get new access tokens |
| **Lifetime** | 15 minutes ⏱️ | 7 days 📅 |
| **Sent** | Every request | Only to `/auth/refresh` |
| **Storage** | Memory/localStorage | HttpOnly cookie 🍪 |
| **If stolen** | Limited damage | Bigger problem! 😱 |

---

### 🔄 Complete Authentication Flow

```mermaid
sequenceDiagram
    participant U as 👤 User
    participant C as 🌐 Client App
    participant S as 🖥️ Server
    participant DB as 💾 Database

    Note over U,DB: 🔐 LOGIN FLOW
    U->>C: Enter email & password
    C->>S: POST /auth/login
    S->>DB: Verify credentials
    DB-->>S: User found ✅
    S->>S: Generate Access Token (15min)
    S->>S: Generate Refresh Token (7days)
    S-->>C: Access Token + Refresh Cookie 🍪
    C->>C: Store access token

    Note over U,DB: 📡 API REQUEST FLOW
    U->>C: Click something
    C->>S: GET /api/data + Bearer token
    S->>S: Validate JWT signature
    S->>S: Check expiration
    S-->>C: Data ✅

    Note over U,DB: 🔄 TOKEN REFRESH FLOW
    C->>S: POST /auth/refresh + Cookie
    S->>S: Validate refresh token
    S-->>C: New Access Token ✅
```

---

### 🛡️ Security Filter Chain

Every request goes through this chain:

```mermaid
flowchart LR
    R["📨 Request"] --> F1["🔍 JwtAuthFilter"]
    F1 --> F2["🔐 UsernamePasswordFilter"]
    F2 --> F3["🛡️ Other Filters..."]
    F3 --> C["🎯 Controller"]
    C --> Response["📬 Response"]
    
    F1 --> |"Has Bearer token?"| V{"Valid?"}
    V --> |"Yes ✅"| Auth["Set Authentication"]
    V --> |"No ❌"| Next["Continue (no auth)"]
    Auth --> F2
    Next --> F2
```

---

### 📝 Key Takeaways

> 🔐 **Session-based** = server stores state (not for APIs)
> 
> 🎫 **Token-based** = stateless JWTs (perfect for REST APIs!)

> 🔒 **PasswordEncoder** hashes passwords with BCrypt
> 
> 🔧 **AuthenticationManager** → **AuthenticationProvider** → **UserDetailsService**

> 🎫 **Access Token** = short-lived, sent on every request
> 
> 🔄 **Refresh Token** = long-lived, stored in HttpOnly cookie

---

## 🚀 Step 1: Project Setup

### 1.1 Create new project

Go to [start.spring.io](https://start.spring.io) and select:

- ☕ Java 21
- 📦 Maven
- 🌱 Spring Boot 3.5+

### 1.2 Start MySQL with Docker

```bash
# Run this command 👇
docker-compose up -d
```

**docker-compose.yml:**

```yaml
services:
  mysql:
    image: mysql:8.0
    container_name: mysql-jwt
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: jwt_db
      MYSQL_USER: jwt_user
      MYSQL_PASSWORD: jwt_password
    ports:
      - '3306:3306'
    volumes:
      - mysql_data:/var/lib/mysql

volumes:
  mysql_data:
```

---

## 📦 Step 2: Add Dependencies

**Add these to your `pom.xml`:**

```xml
<!-- 🛡️ Spring Security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- 🌐 Spring Web -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>

<!-- 💾 Spring Data JPA -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>

<!-- ✅ Validation -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>

<!-- 🔐 JWT Library (3 parts!) -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.6</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.5</version>
</dependency>

<!-- 🤖 Lombok (less code!) -->
<dependency>
    <groupId>org.projectlombok</groupId>
    <artifactId>lombok</artifactId>
    <optional>true</optional>
</dependency>

<!-- 🐬 MySQL -->
<dependency>
    <groupId>com.mysql</groupId>
    <artifactId>mysql-connector-j</artifactId>
    <scope>runtime</scope>
</dependency>

<!-- 🦅 Flyway (database migrations) -->
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-core</artifactId>
</dependency>
<dependency>
    <groupId>org.flywaydb</groupId>
    <artifactId>flyway-mysql</artifactId>
</dependency>
```

---

## 💾 Step 3: Database Setup

### 3.1 Configure application.yaml

```yaml
spring:
  application:
    name: jwt

  # 🔐 JWT Settings
  jwt:
    secret: 1fa82d5d9bd65b86c8052850ce001398 # 🔑 Your secret key (32+ chars!)
    accessTokenExpiration: 900 # ⏱️ 15 minutes (in seconds)
    refreshTokenExpiration: 604800 # 🔄 7 days (in seconds)

  # 💾 Database
  datasource:
    url: jdbc:mysql://localhost:3306/jwt_db
    username: jwt_user
    password: jwt_password
    driver-class-name: com.mysql.cj.jdbc.Driver

  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true

  # 🦅 Flyway migrations
  flyway:
    enabled: true
    baseline-on-migrate: true

server:
  port: 8087
```

### 3.2 Create Database Migration

**File:** `src/main/resources/db/migration/V1__initial_migration.sql`

```sql
CREATE TABLE users (
    id       BIGINT AUTO_INCREMENT NOT NULL,
    name     VARCHAR(255) NOT NULL,
    email    VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role     VARCHAR(20) DEFAULT 'USER' NOT NULL,
    PRIMARY KEY (id)
);
```

---

## 👤 Step 4: Create User Entity

### 4.1 Role Enum

```java
// 📁 user/Role.java
public enum Role {
    USER,
    ADMIN
}
```

### 4.2 User Entity

```java
// 📁 user/User.java
@Entity
@Table(name = "users")
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;
}
```

### 4.3 User Repository

```java
// 📁 user/UserRepository.java
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}
```

### 4.4 UserDetailsService

```java
// 📁 user/UserDetailsServiceImpl.java
@Service
@AllArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) {
        var user = userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return new User(
            user.getEmail(),
            user.getPassword(),
            Collections.emptyList()
        );
    }
}
```

---

## ⚙️ Step 5: JWT Configuration

### 5.1 JwtConfig Class

> 📝 **This class reads JWT settings from application.yaml**

```java
// 📁 security/JwtConfig.java
@Configuration
@ConfigurationProperties(prefix = "spring.jwt")  // 🔗 Links to application.yaml
@Data
public class JwtConfig {
    private String secret;                  // 🔑 Secret key
    private int accessTokenExpiration;      // ⏱️ 15 min
    private int refreshTokenExpiration;     // 🔄 7 days

    // 🔧 Convert string to crypto key
    public SecretKey getSecretKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }
}
```

### 5.2 Jwt Token Class

```java
// 📁 security/Jwt.java
@AllArgsConstructor
public class Jwt {
    private final Claims claims;      // 📋 Token data
    private final SecretKey secretKey;

    // ⏰ Is token expired?
    public boolean isExpired() {
        return claims.getExpiration().before(new Date());
    }

    // 🆔 Get user ID
    public long getUserId() {
        return Long.valueOf(claims.getSubject());
    }

    // 👑 Get user role
    public Role getRole() {
        return Role.valueOf(claims.get("role", String.class));
    }

    // 🎨 Convert to string
    public String toString() {
        return Jwts.builder()
            .claims(claims)
            .signWith(secretKey)
            .compact();
    }
}
```

---

## 🎫 Step 6: JWT Service

> 📝 **This class creates and validates JWT tokens**

```java
// 📁 security/JwtService.java
@Service
@AllArgsConstructor
public class JwtService {
    private final JwtConfig jwtConfig;

    // 🎫 Create access token (short-lived: 15 min)
    public Jwt generateAccessToken(User user) {
        return generateToken(user, jwtConfig.getAccessTokenExpiration());
    }

    // 🔄 Create refresh token (long-lived: 7 days)
    public Jwt generateRefreshToken(User user) {
        return generateToken(user, jwtConfig.getRefreshTokenExpiration());
    }

    // 🔨 Core token creation
    private Jwt generateToken(User user, int expiration) {
        var claims = Jwts.claims()
            .subject(user.getId().toString())         // 🆔 User ID
            .add("email", user.getEmail())            // 📧 Email
            .add("name", user.getName())              // 📛 Name
            .add("role", user.getRole())              // 👑 Role
            .issuedAt(new Date())                     // 📅 Created now
            .expiration(new Date(System.currentTimeMillis()
                + 1000L * expiration))                // ⏰ Expires in X seconds
            .build();

        return new Jwt(claims, jwtConfig.getSecretKey());
    }

    // 🔍 Parse token string → Jwt object
    public Jwt parseToken(String token) {
        try {
            var claims = Jwts.parser()
                .verifyWith(jwtConfig.getSecretKey())  // ✅ Verify signature
                .build()
                .parseSignedClaims(token)
                .getPayload();
            return new Jwt(claims, jwtConfig.getSecretKey());
        } catch (JwtException e) {
            return null;  // ❌ Invalid token
        }
    }
}
```

---

## 🔍 Step 7: JWT Authentication Filter

> 📝 **This filter checks every request for a valid JWT token**

```java
// 📁 security/JwtAuthenticationFilter.java
@Component
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // 📋 Get Authorization header
        var authHeader = request.getHeader("Authorization");

        // ❌ No token? Skip!
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 🎫 Extract token (remove "Bearer ")
        var token = authHeader.replace("Bearer ", "");
        var jwt = jwtService.parseToken(token);

        // ❌ Invalid or expired? Skip!
        if (jwt == null || jwt.isExpired()) {
            filterChain.doFilter(request, response);
            return;
        }

        // ✅ Valid token! Set authentication
        var authentication = new UsernamePasswordAuthenticationToken(
            jwt.getUserId(),                                    // 🆔 User ID
            null,                                               // 🔑 No password needed
            List.of(new SimpleGrantedAuthority("ROLE_" + jwt.getRole()))  // 👑 Role
        );
        authentication.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request)
        );

        // 🛡️ Save to security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        filterChain.doFilter(request, response);
    }
}
```

---

## 🛡️ Step 8: Security Configuration

### 8.1 SecurityRules Interface

```java
// 📁 common/SecurityRules.java
public interface SecurityRules {
    void configure(
        AuthorizeHttpRequestsConfigurer<HttpSecurity>
            .AuthorizationManagerRequestMatcherRegistry registry
    );
}
```

### 8.2 Auth Security Rules

```java
// 📁 security/AuthSecurityRules.java
@Component
public class AuthSecurityRules implements SecurityRules {
    @Override
    public void configure(...) {
        registry
            .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()   // ✅ Public
            .requestMatchers(HttpMethod.POST, "/auth/refresh").permitAll(); // ✅ Public
    }
}
```

### 8.3 Main Security Config

```java
// 📁 security/SecurityConfig.java
@Configuration
@EnableWebSecurity
@AllArgsConstructor
public class SecurityConfig {
    private final UserDetailsService userDetailsService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final List<SecurityRules> featureSecurityRules;

    // 🔒 Password encoder (BCrypt)
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 🔐 Authentication provider
    @Bean
    public AuthenticationProvider authenticationProvider() {
        var provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }

    // 🔐 Authentication manager
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // 🛡️ Security filter chain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // 🚫 Stateless (no sessions!)
            .sessionManagement(c ->
                c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // 🚫 Disable CSRF (JWT handles security)
            .csrf(AbstractHttpConfigurer::disable)
            // 🔐 URL rules
            .authorizeHttpRequests(c -> {
                featureSecurityRules.forEach(r -> r.configure(c));
                c.anyRequest().authenticated();  // 🔒 All other = login required
            })
            // 🔍 Add JWT filter
            .addFilterBefore(jwtAuthenticationFilter,
                UsernamePasswordAuthenticationFilter.class)
            // 🚨 Error handling
            .exceptionHandling(c -> {
                c.authenticationEntryPoint(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED));  // 401
                c.accessDeniedHandler((req, res, ex) ->
                    res.setStatus(HttpStatus.FORBIDDEN.value()));        // 403
            });

        return http.build();
    }
}
```

---

## 🌐 Step 9: Auth Controller

### 9.1 Request/Response DTOs

```java
// 📁 security/LoginRequest.java
@Data
public class LoginRequest {
    @NotBlank
    private String email;
    @NotBlank
    private String password;
}

// 📁 security/LoginResponse.java
@Data @AllArgsConstructor
public class LoginResponse {
    private Jwt accessToken;
    private Jwt refreshToken;
}

// 📁 security/JwtResponse.java
public record JwtResponse(String accessToken) {}
```

### 9.2 Auth Service

```java
// 📁 security/AuthService.java
@Service
@AllArgsConstructor
public class AuthService {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    // 👤 Get current logged-in user
    public User getCurrentUser() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        var userId = (long) auth.getPrincipal();
        return userRepository.findById(userId).orElse(null);
    }

    // 🔐 Login and get tokens
    public LoginResponse login(LoginRequest request) {
        // ✅ Validate credentials
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request.getPassword()
            )
        );

        // 🔍 Get user from DB
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        // 🎫 Generate tokens
        var accessToken = jwtService.generateAccessToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        return new LoginResponse(accessToken, refreshToken);
    }

    // 🔄 Get new access token using refresh token
    public Jwt refreshAccessToken(String refreshToken) {
        var jwt = jwtService.parseToken(refreshToken);

        if (jwt == null || jwt.isExpired()) {
            throw new BadCredentialsException("Invalid refresh token");
        }

        var user = userRepository.findById(jwt.getUserId()).orElseThrow();
        return jwtService.generateAccessToken(user);
    }
}
```

### 9.3 Auth Controller

```java
// 📁 security/AuthController.java
@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthController {
    private final JwtConfig jwtConfig;
    private final AuthService authService;

    // 🔐 POST /auth/login
    @PostMapping("/login")
    public JwtResponse login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response) {

        var loginResult = authService.login(request);

        // 🍪 Store refresh token in HTTP-only cookie
        var cookie = new Cookie("refreshToken",
            loginResult.getRefreshToken().toString());
        cookie.setHttpOnly(true);       // 🔒 No JavaScript access
        cookie.setPath("/auth/refresh");
        cookie.setMaxAge(jwtConfig.getRefreshTokenExpiration());
        cookie.setSecure(true);         // 🔒 HTTPS only
        response.addCookie(cookie);

        // 📬 Return access token
        return new JwtResponse(loginResult.getAccessToken().toString());
    }

    // 🔄 POST /auth/refresh
    @PostMapping("/refresh")
    public JwtResponse refresh(
            @CookieValue("refreshToken") String refreshToken) {
        var accessToken = authService.refreshAccessToken(refreshToken);
        return new JwtResponse(accessToken.toString());
    }

    // 👤 GET /auth/me
    @GetMapping("/me")
    public ResponseEntity<UserDto> me() {
        var user = authService.getCurrentUser();
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(userMapper.toDto(user));
    }

    // 🚨 Handle bad credentials
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Void> handleBadCredentials() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}
```

---

## 🧪 Step 10: Test the API

### 10.1 Start the App

```bash
# 🐳 Start MySQL
docker-compose up -d

# 🚀 Run the app
mvn spring-boot:run
```

### 10.2 Test with cURL or Postman

#### 📝 Register a User (add this endpoint if needed)

```bash
curl -X POST http://localhost:8087/users/register \
  -H "Content-Type: application/json" \
  -d '{"name":"John","email":"john@test.com","password":"secret123","role":"USER"}'
```

#### 🔐 Login

```bash
curl -X POST http://localhost:8087/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@test.com","password":"secret123"}'
```

**Response:**

```json
{
  "accessToken": "eyJhbGciOiJIUzM4NCJ9.eyJzdWI..."
}
```

#### 👤 Get Current User

```bash
curl http://localhost:8087/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzM4NCJ9.eyJzdWI..."
```

#### 🔄 Refresh Token

```bash
curl -X POST http://localhost:8087/auth/refresh \
  --cookie "refreshToken=eyJhbGciOiJIUzM4NCJ9..."
```

---

## 📁 Project Structure

```
src/main/java/com/example/jwt/
├── 🚀 JwtApplication.java
├── 📁 common/
│   └── SecurityRules.java
├── 📁 security/
│   ├── AuthController.java      # 🌐 REST endpoints
│   ├── AuthSecurityRules.java   # 🔓 Public endpoints
│   ├── AuthService.java         # 🔐 Business logic
│   ├── Jwt.java                 # 🎫 Token wrapper
│   ├── JwtAuthenticationFilter.java  # 🔍 Request filter
│   ├── JwtConfig.java           # ⚙️ Configuration
│   ├── JwtResponse.java         # 📬 Response DTO
│   ├── JwtService.java          # 🔧 Token operations
│   ├── LoginRequest.java        # 📨 Request DTO
│   ├── LoginResponse.java       # 📬 Internal response
│   └── SecurityConfig.java      # 🛡️ Security setup
└── 📁 user/
    ├── Role.java                # 👑 USER/ADMIN
    ├── User.java                # 👤 Entity
    ├── UserController.java      # 🌐 CRUD endpoints
    ├── UserDetailsServiceImpl.java  # 🔐 Security integration
    ├── UserRepository.java      # 💾 Database access
    └── UserService.java         # 📋 Business logic
```

---

## 🎯 Quick Reference

| What                | Where                                                   |
| ------------------- | ------------------------------------------------------- |
| 🔑 Secret key       | `application.yaml` → `spring.jwt.secret`                |
| ⏱️ Token expiration | `application.yaml` → `spring.jwt.accessTokenExpiration` |
| 🎫 Create tokens    | `JwtService.java`                                       |
| 🔍 Validate tokens  | `JwtAuthenticationFilter.java`                          |
| 🛡️ Security rules   | `SecurityConfig.java`                                   |
| 🔓 Public endpoints | `AuthSecurityRules.java`                                |

---

## ⚠️ Security Tips

1. **🔑 Secret key** - Use 32+ random characters in production!
2. **🍪 HTTP-only cookies** - Refresh tokens are safer in cookies
3. **⏱️ Short access tokens** - 15 minutes is good
4. **🔒 HTTPS only** - Always use HTTPS in production
5. **🚫 Never log tokens** - They are like passwords!

---

## 🤝 Need Help?

1. Check the **postman-collection.txt** for API examples
2. Look at the **existing code** - it has lots of comments! 💬
3. Read Spring Security docs: [spring.io/security](https://spring.io/projects/spring-security)

---

**Happy coding! 🚀**

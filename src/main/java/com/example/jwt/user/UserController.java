// 📦 Package declaration - user management classes
package com.example.jwt.user;

// ✅ Validation - ensures request data is valid before processing
import jakarta.validation.Valid;
// 🗺️ Java Map - for key-value pairs (like error responses)
import java.util.Map;
// 🤖 Lombok - auto-generates constructor with all fields
import lombok.AllArgsConstructor;
// 🌐 Spring Web - HTTP status codes and response handling
import org.springframework.http.HttpStatus;
// 📬 ResponseEntity - represents HTTP response with headers, body, and status
import org.springframework.http.ResponseEntity;
// 🚫 Security exception - thrown when user lacks permission
import org.springframework.security.access.AccessDeniedException;
// 🌐 Spring Web MVC - annotations for REST API endpoints
import org.springframework.web.bind.annotation.*;
// 🔗 URI builder - for creating location headers in POST responses
import org.springframework.web.util.UriComponentsBuilder;

// 🌐 @RestController - Tells Spring "Hey! This class handles HTTP requests!"
// Combines @Controller and @ResponseBody - automatically serializes responses to JSON
@RestController
// 🤖 @AllArgsConstructor - Lombok magic: creates constructor with all fields (userService)
@AllArgsConstructor
// 🛣️ @RequestMapping - Base URL path for all endpoints in this controller ("/users")
@RequestMapping("/users")
public class UserController {
    // 🔧 User service - contains business logic for user operations
    private final UserService userService;

    // 📖 GET /users - Retrieve all users with optional sorting
    @GetMapping
    public Iterable<UserDto> getAllUsers(
        // 📝 Query parameter - optional sort field (default: empty string)
        @RequestParam(required = false, defaultValue = "", name = "sort") String sortBy
    ) {
        // 🔧 Delegate to service layer for business logic
        return userService.getAllUsers(sortBy);
    }

    // 📖 GET /users/{id} - Retrieve a specific user by ID
    @GetMapping("/{id}")
    // 🛤️ @PathVariable - Extracts user ID from URL path
    public UserDto getUser(@PathVariable Long id) {
        // 🔧 Delegate to service layer for business logic
        return userService.getUser(id);
    }

    // 📝 POST /users - Register a new user
    @PostMapping
    // ✅ @Valid - Validates request body before processing
    // 📦 @RequestBody - Converts JSON request body to Java object
    public ResponseEntity<?> registerUser(
            @Valid @RequestBody RegisterUserRequest request,
            // 🔗 UriComponentsBuilder - builds location header for created resource
            UriComponentsBuilder uriBuilder) {

        // 🔧 Register user and get back user data
        var userDto = userService.registerUser(request);
        // 🔗 Build URI for newly created user (e.g., /users/123)
        var uri = uriBuilder.path("/users/{id}").buildAndExpand(userDto.getId()).toUri();
        // 📬 Return 201 Created with location header and user data
        return ResponseEntity.created(uri).body(userDto);
    }

    // ✏️ PUT /users/{id} - Update an existing user
    @PutMapping("/{id}")
    public UserDto updateUser(
        // 🛤️ @PathVariable - Extracts user ID from URL path
        @PathVariable(name = "id") Long id,
        // 📦 @RequestBody - Converts JSON request body to Java object
        @RequestBody UpdateUserRequest request) {
        // 🔧 Delegate to service layer for business logic
        return userService.updateUser(id, request);
    }

    // 🗑️ DELETE /users/{id} - Delete a user
    @DeleteMapping("/{id}")
    public void deleteUser(@PathVariable Long id) {
        // 🔧 Delegate to service layer for business logic
        userService.deleteUser(id);
    }

    // 🔐 POST /users/{id}/change-password - Change user's password
    @PostMapping("/{id}/change-password")
    public void changePassword(
            // 🛤️ @PathVariable - Extracts user ID from URL path
            @PathVariable Long id,
            // 📦 @RequestBody - Converts JSON request body to Java object
            @RequestBody ChangePasswordRequest request) {
        // 🔧 Delegate to service layer for business logic
        userService.changePassword(id, request);
    }

    // 🚨 Exception handler - handles duplicate user registration
    @ExceptionHandler(DuplicateUserException.class)
    // 📬 Returns 400 Bad Request with error details
    public ResponseEntity<Map<String, String>> handleDuplicateUser() {
        // 📄 Return error message about duplicate email
        return ResponseEntity.badRequest().body(
            Map.of("email", "Email is already registered.")
        );
    }

    // 🚨 Exception handler - handles user not found errors
    @ExceptionHandler(UserNotFoundException.class)
    // 📬 Returns 404 Not Found with empty body
    public ResponseEntity<Void> handleUserNotFound() {
        // 📄 Return 404 status (user doesn't exist)
        return ResponseEntity.notFound().build();
    }

    // 🚨 Exception handler - handles access denied errors
    @ExceptionHandler(AccessDeniedException.class)
    // 📬 Returns 401 Unauthorized with empty body
    public ResponseEntity<Void> handleAccessDenied() {
        // 📄 Return 401 status (user lacks permission)
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }
}

// 🚀 Package declaration - main application package
package com.example.jwt;

// 🌱 Spring Boot - SpringApplication class to bootstrap the application
import org.springframework.boot.SpringApplication;
// ⚙️ Spring Boot - @SpringBootApplication enables auto-configuration, component scanning, and configuration
import org.springframework.boot.autoconfigure.SpringBootApplication;

// 🌱 @SpringBootApplication - Combo of @Configuration, @EnableAutoConfiguration, and @ComponentScan
// This annotation tells Spring "Hey! This is the main application class!"
@SpringBootApplication
public class JwtApplication {

	// 🎯 Main method - Java entry point when the application starts
	public static void main(String[] args) {
		// 🚀 Launch the Spring Boot application with all its magic!
		// Spring will scan for beans, configure the database, start the web server, etc.
		SpringApplication.run(JwtApplication.class, args);
	}

}

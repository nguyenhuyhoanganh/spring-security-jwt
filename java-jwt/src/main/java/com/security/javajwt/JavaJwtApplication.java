package com.security.javajwt;

import com.security.javajwt.domain.Role;
import com.security.javajwt.domain.User;
import com.security.javajwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JavaJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(JavaJwtApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.addUser(new User(null, "Member", "member", "1", new ArrayList<>()));
            userService.addUser(new User(null, "Admin", "admin", "1", new ArrayList<>()));
            userService.addUser(new User(null, "Manager", "manager", "1", new ArrayList<>()));

            userService.addRole(new Role(null, "ROLE_USER"));
            userService.addRole(new Role(null, "ROLE_ADMIN"));
            userService.addRole(new Role(null, "ROLE_MANAGER"));

            userService.addRoletoUser("ROLE_USER", "member");
            userService.addRoletoUser("ROLE_USER", "manager");
            userService.addRoletoUser("ROLE_USER", "admin");
            userService.addRoletoUser("ROLE_MANAGER", "manager");
            userService.addRoletoUser("ROLE_MANAGER", "admin");
            userService.addRoletoUser("ROLE_ADMIN", "admin");
        };
    }
}

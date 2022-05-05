package com.security.javajwt.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.javajwt.domain.Role;
import com.security.javajwt.domain.User;
import com.security.javajwt.dto.ErrorResponseDTO;
import com.security.javajwt.dto.ResponseDTO;
import com.security.javajwt.service.UserService;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.security.javajwt.constants.SecurityConstants.SECRET_KEY;
import static com.security.javajwt.constants.SecurityConstants.TOKEN_PREFIX;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequestMapping("/api")
public class UserResource {
    @Autowired
    private UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok().body(userService.getAllUsers());
    }

    @GetMapping("/user/{username}")
    public ResponseEntity<User> getUser(@RequestParam String username) {
        return ResponseEntity.ok().body(userService.getUser(username));
    }

    @PostMapping("/user")
    public ResponseEntity<User> addUser(@RequestBody User user) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user").toUriString());
        return ResponseEntity.created(uri).body(userService.addUser(user));
    }

    @PostMapping("/role")
    public ResponseEntity<Role> addRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role").toUriString());
        return ResponseEntity.created(uri).body(userService.addRole(role));
    }

    @PostMapping("user/add-role")
    public ResponseEntity<?> addRoleToUser(@RequestBody AddRole addRole) {
        userService.addRoletoUser(addRole.getRoleName(), addRole.getUsername());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/refresh-token")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if (authorizationHeader != null && authorizationHeader.startsWith(TOKEN_PREFIX)) {

                String refresh_token = authorizationHeader.substring(TOKEN_PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(refresh_token);
                String username = decodedJWT.getSubject();
                User user = userService.getUser(username);
                String access_token = JWT.create().withSubject(user.getUsername()).withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)).withIssuer(request.getRequestURL().toString()).withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList())).sign(algorithm);
                Map<String, String> tokens = new HashMap<>();
                tokens.put("access_token", access_token);
                tokens.put("refresh_token", refresh_token);
                response.setContentType(APPLICATION_JSON_VALUE);
                response.setStatus(HttpStatus.CREATED.value());
                ResponseDTO<Map<String, String>> responseDTO = new ResponseDTO<>(HttpStatus.CREATED.value(), request.getServletPath());
                responseDTO.setData(tokens);
                new ObjectMapper().writeValue(response.getOutputStream(), responseDTO);
            } else {
                throw new RuntimeException("Refresh token is missing");
            }
        } catch (Exception exception) {
            response.setHeader("error", exception.getMessage());
            response.setContentType(APPLICATION_JSON_VALUE);
            response.setStatus(HttpStatus.FORBIDDEN.value());
            ErrorResponseDTO errorResponseDTO = new ErrorResponseDTO(HttpStatus.FORBIDDEN.value(), exception.getMessage(), request.getServletPath());
            new ObjectMapper().writeValue(response.getOutputStream(), errorResponseDTO);
        }
    }
}

@Data
class AddRole {
    private String username;
    private String roleName;
}

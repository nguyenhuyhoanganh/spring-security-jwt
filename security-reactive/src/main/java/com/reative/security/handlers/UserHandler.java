package com.reative.security.handlers;

import com.reative.security.model.User;
import com.reative.security.service.UserService;
import com.reative.security.utils.JwtTokenProvider;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

@Component
@AllArgsConstructor
public class UserHandler {
    private final UserService service;
    private final ReactiveAuthenticationManager authenticationManager;
    private JwtTokenProvider jwtTokenProvider;

    public Mono<ServerResponse> getALl(ServerRequest request) {
        return ServerResponse.ok().contentType(MediaType.TEXT_EVENT_STREAM).body(service.getAll(), User.class);
    }

    public Mono<ServerResponse> login(ServerRequest request) {
        return ServerResponse.ok().contentType(MediaType.TEXT_EVENT_STREAM)
                .body(request.bodyToMono(AuthenticationRequest.class)
                        .flatMap(login -> this.authenticationManager
                                .authenticate(new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()))
                                .map(this.jwtTokenProvider::generateAccessToken)
                        ), String.class);
    }
}

@Data
class AuthenticationRequest {
    private String username;

    private String password;
}

package com.reative.security.config;

import com.reative.security.handlers.UserHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

@Configuration
public class RoutesConfig {

    @Bean
    public RouterFunction<ServerResponse> router(UserHandler handler) {
        return RouterFunctions.route().GET("/users", handler::getALl)
                .POST("/login", handler::login).build();
    }
}

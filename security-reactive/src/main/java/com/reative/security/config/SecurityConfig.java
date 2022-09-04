package com.reative.security.config;

import com.reative.security.filter.CustomAuthenticationFilter;
import com.reative.security.utils.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Mono;

@Configuration
public class SecurityConfig {

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public ReactiveAuthenticationManager reactiveAuthenticationManager
          (ReactiveUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
    var authenticationManager = new UserDetailsRepositoryReactiveAuthenticationManager(userDetailsService);
    authenticationManager.setPasswordEncoder(passwordEncoder);
    return authenticationManager;
  }

  @Bean
  SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http,
                                              JwtTokenProvider tokenProvider,
                                              ReactiveAuthenticationManager reactiveAuthenticationManager) {

    return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
            .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
            .authenticationManager(reactiveAuthenticationManager)
            .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
            .authorizeExchange(it -> it
                    .pathMatchers(HttpMethod.GET, "/users/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                    .pathMatchers(HttpMethod.POST, "/users/**").hasAnyAuthority("ROLE_ADMIN")
                    .pathMatchers("/login", "/refresh-token/**").permitAll()
                    .anyExchange().permitAll()
            )
            .addFilterAt(new CustomAuthenticationFilter(tokenProvider), SecurityWebFiltersOrder.HTTP_BASIC)
            .build();
  }

  private Mono<AuthorizationDecision> currentUserMatchesPath(Mono<Authentication> authentication,
                                                             AuthorizationContext context) {
    return authentication
            .map(a -> context.getVariables().get("user").equals(a.getName()))
            .map(AuthorizationDecision::new);
  }
}

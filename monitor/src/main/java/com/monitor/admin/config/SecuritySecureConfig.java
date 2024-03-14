package com.monitor.admin.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

// https://docs.spring-boot-admin.com/current/security.html
@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class SecuritySecureConfig {

    private final AdminServerProperties adminServer;

    @Bean
    protected SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
       return http.authorizeExchange(exchanges ->
                                             exchanges
                                                     .pathMatchers("/assets/**").permitAll()
                                                     .pathMatchers("/actuator/**").permitAll()
                                                     .pathMatchers(adminServer.path("/login")).permitAll()
                                                     .pathMatchers(adminServer.path("/instances")).permitAll()
                                                     .pathMatchers(adminServer.path("/instances/*")).permitAll()
                                                     .anyExchange().authenticated())
               .formLogin(formLoginSpec -> formLoginSpec.loginPage(this.adminServer.path("/login")))
               .logout(logoutSpec -> logoutSpec.logoutUrl(this.adminServer.path("/logout")))
               .httpBasic(Customizer.withDefaults())
               .csrf(csrfSpec -> csrfSpec.disable())
               .build();
    }
}
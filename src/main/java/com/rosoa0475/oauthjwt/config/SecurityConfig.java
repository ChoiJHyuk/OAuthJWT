package com.rosoa0475.oauthjwt.config;

import com.rosoa0475.oauthjwt.jwt.JWTFilter;
import com.rosoa0475.oauthjwt.jwt.JWTUtil;
import com.rosoa0475.oauthjwt.oauth2.custom.CustomOAuth2UserService;
import com.rosoa0475.oauthjwt.oauth2.custom.CustomSuccessHandler;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JWTUtil jwtUtil;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientService authorizedClientService;

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_A > ROLE_B\n"
                + "ROLE_B > ROLE_C\n");
        return roleHierarchy;
    }


    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                //포트번호가 달라 데이터가 안 보이는 것을 방지하기 위해 cors 설정해줘야함
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();
                        //프론트의 포트번호 지정
                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        //post, get 등 모든 메소드 허용
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        //Credentials 이란 쿠키, 인증헤더, TLS client certificates(증명서)를 말함
                        //쿠키를 사용하므로 Credentials 허용 해준다.
                        configuration.setAllowCredentials(true);
                        //모든 헤더 받을 수 있도록 허용
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);
                        //우리가 줄 데이터를 정의해준다. 쿠키를 줘야하므로 먼저 Set-Cookie 해줌
                        //이후 토큰을 위해 Authorization도 정의해준다.
                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }
                }));

        http
                .csrf(AbstractHttpConfigurer::disable);
        http
                .formLogin(AbstractHttpConfigurer::disable);
        http
                .httpBasic(AbstractHttpConfigurer::disable);
        http
                .oauth2Login((oauth) -> oauth
                        .userInfoEndpoint((userInfoEndpoint) -> userInfoEndpoint
                                .userService(customOAuth2UserService))
                        .authorizedClientService(authorizedClientService)
                        .successHandler(customSuccessHandler)
                        .clientRegistrationRepository(clientRegistrationRepository));
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/oauth2/**", "/login/**").permitAll()
                        .anyRequest().authenticated());
        http
                //재로그인 무한 루프 방지 하기 위해
                .addFilterAfter(new

                        JWTFilter(jwtUtil), OAuth2LoginAuthenticationFilter.class);
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}

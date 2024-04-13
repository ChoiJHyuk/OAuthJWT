package com.rosoa0475.oauthjwt.jwt;

import com.rosoa0475.oauthjwt.domain.UserEntity;
import com.rosoa0475.oauthjwt.dto.CustomOAuth2User;
import com.rosoa0475.oauthjwt.dto.KakaoResponse;
import com.rosoa0475.oauthjwt.dto.OAuth2Response;
import com.rosoa0475.oauthjwt.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {
    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = null;

        Cookie[] cookies = request.getCookies();
        for(Cookie cookie : cookies) {
            System.out.println(cookie.getName());
            if(cookie.getName().equals("Authorization")) {
                authorization = cookie.getValue();
            }
        }
        if(authorization == null) {
            System.out.println("token null");
            filterChain.doFilter(request, response);
            return;
        }
        String token = authorization;

        if(jwtUtil.isExpired(token)){
            System.out.println("token expired");
            filterChain.doFilter(request, response);
            return;
        }

        String nickname = jwtUtil.getNickname(token);
        String role = jwtUtil.getRole(token);
        UserDTO userDTO = new UserDTO();
        userDTO.setNickname(nickname);
        userDTO.setRole(role);
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);
        Authentication auth = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
        filterChain.doFilter(request, response);
    }
}

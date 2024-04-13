package com.rosoa0475.oauthjwt.oauth2;

import com.rosoa0475.oauthjwt.dto.CustomOAuth2User;
import com.rosoa0475.oauthjwt.jwt.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        CustomOAuth2User customOAuth2User = (CustomOAuth2User) authentication.getPrincipal();
        String nickname = customOAuth2User.getName();

        Collection<? extends GrantedAuthority> authorities = customOAuth2User.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority authority = iterator.next();
        String role = authority.getAuthority();

        String token = jwtUtil.createJwt(nickname,role, 60*60*60L);
        //프론트에 jwt 토큰 던져주는 방법 하이퍼링킹 방식이므로 헤더에 써주면 안 된다.
        response.addCookie(createCookie("Authorization", token));
        response.sendRedirect("http://localhost:8080/");

    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        //쿠키가 살아있을 시간
        cookie.setMaxAge(60*60*60);
        //쿠키가 보일 위치 "/"로 설정하면 전역으로 처리 됨
        cookie.setPath("/");
        //javascript가 쿠키 못 가져가게 http only
        cookie.setHttpOnly(true);
        //https통신에서만 쿠키가 사용되도록하는 메소드
        //cookie.setSecure(true);
        return cookie;
    }
}

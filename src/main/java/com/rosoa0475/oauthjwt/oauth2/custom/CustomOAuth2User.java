package com.rosoa0475.oauthjwt.oauth2.custom;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

//                  UserDetails와 유사
public class CustomOAuth2User implements OAuth2User {
    @Getter
    private final Long userId;
    private final String name;
    private final String role;

    public CustomOAuth2User(Long userId, String name, String role) {
        this.userId = userId;
        this.name = name;
        this.role = role;
    }

    public CustomOAuth2User(Long userId, String role) {
        this.userId = userId;
        this.name = null;
        this.role = role;
    }
    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(role));
        return authorities;
    }

    @Override
    public String getName() {
        return name;
    }
}

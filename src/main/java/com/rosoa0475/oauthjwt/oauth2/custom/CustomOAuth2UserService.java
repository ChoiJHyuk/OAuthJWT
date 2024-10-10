package com.rosoa0475.oauthjwt.oauth2.custom;

import com.rosoa0475.oauthjwt.domain.UserEntity;
import com.rosoa0475.oauthjwt.oauth2.response.KakaoResponse;
import com.rosoa0475.oauthjwt.oauth2.response.OAuth2Response;
import com.rosoa0475.oauthjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
//                          UserDetailsService와 유사
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User.getAttributes());

        OAuth2Response oAuth2Response = new KakaoResponse(oAuth2User.getAttributes());

        String role = "ROLE_USER";

        Optional<UserEntity> byRegistrationId = userRepository
                .findByRegistrationId(oAuth2Response.getRegistrationId());
        UserEntity user;
        if (byRegistrationId.isPresent()) {
            user = byRegistrationId.get();
            user.setNickname(oAuth2Response.getnickname());
        } else {
            user = new UserEntity();
            user.setNickname(oAuth2Response.getnickname());
            user.setRegistrationId(oAuth2Response.getRegistrationId());
            user.setRole(role);
            userRepository.save(user);
        }
        return new CustomOAuth2User(user.getId(), user.getNickname(), role);
    }
}

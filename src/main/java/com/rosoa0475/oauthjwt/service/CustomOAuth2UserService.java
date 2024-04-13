package com.rosoa0475.oauthjwt.service;

import com.rosoa0475.oauthjwt.domain.UserEntity;
import com.rosoa0475.oauthjwt.dto.CustomOAuth2User;
import com.rosoa0475.oauthjwt.dto.KakaoResponse;
import com.rosoa0475.oauthjwt.dto.OAuth2Response;
import com.rosoa0475.oauthjwt.dto.UserDTO;
import com.rosoa0475.oauthjwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        OAuth2Response oAuth2Response = new KakaoResponse(oAuth2User.getAttributes());

        String role = "ROLE_USER";
        /*
        * 디비에 검색해서 이미 존재하면 업데이트 해주고
        * 없으면 디비에 새로 저장해주는 로직
        * */

        UserDTO userDTO = new UserDTO();
        userDTO.setRole(role);
        userDTO.setNickname(oAuth2Response.getnickname());
        UserEntity userEntity = new UserEntity();
        userEntity.setNickname(oAuth2Response.getnickname());
        userEntity.setRole(role);

        userRepository.save(userEntity);

        return new CustomOAuth2User(userDTO);
    }
}

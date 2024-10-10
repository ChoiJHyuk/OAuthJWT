package com.rosoa0475.oauthjwt.oauth2.response;

import java.util.Map;

public class KakaoResponse implements OAuth2Response {

    private final Map<String, Object> attribute;
    private final Map<String, Object> profile;

    public KakaoResponse(Map<String, Object> attribute) {
        this.attribute = attribute;
        this.profile = (Map<String, Object>) ((Map<String, Object>) attribute
                .get("kakao_account")).get("profile");
    }


    @Override
    public String getnickname() {
        return profile.get("nickname").toString();
    }

    @Override
    public Long getRegistrationId() {
        return (Long) attribute.get("id");
    }
}

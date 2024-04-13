package com.rosoa0475.oauthjwt.dto;

import java.util.Map;

public class KakaoResponse implements OAuth2Response{

    private final Map<String, Object> attribute;

    public KakaoResponse(Map<String, Object> attribute) {
        this.attribute = (Map<String,Object>)((Map<String,Object>)attribute.get("kakao_account")).get("profile");
    }



    @Override
    public String getnickname() {
        return attribute.get("nickname").toString();
    }

}

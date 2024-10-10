package com.rosoa0475.oauthjwt.controller;

import com.rosoa0475.oauthjwt.oauth2.custom.CustomOAuth2User;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
    @GetMapping("/")
    @ResponseBody
    public String mainAPI(@AuthenticationPrincipal CustomOAuth2User user) {
        return user.getUserId().toString();
    }
}

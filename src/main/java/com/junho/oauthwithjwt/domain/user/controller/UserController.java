package com.junho.oauthwithjwt.domain.user.controller;

import com.junho.oauthwithjwt.domain.user.dto.UserSignUpDto;
import com.junho.oauthwithjwt.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/sign-up")
    private String signUp(@RequestBody UserSignUpDto userSignUpDto) throws Exception {

        userService.signUp(userSignUpDto);

        return "회원가입 성공";
    }

    @GetMapping("/jwt-test")
    private String jwtTest() {

        return "jwtTest 요청 성공";
    }
}

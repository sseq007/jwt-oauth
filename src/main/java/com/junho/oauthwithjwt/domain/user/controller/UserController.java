package com.junho.oauthwithjwt.domain.user.controller;

import com.junho.oauthwithjwt.domain.user.dto.TokenDto;
import com.junho.oauthwithjwt.domain.user.dto.UserSignUpDto;
import com.junho.oauthwithjwt.domain.user.service.UserService;
import com.junho.oauthwithjwt.global.handler.CMRespDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    private ResponseEntity<?> jwtTest() {

        return new ResponseEntity(new CMRespDto<>(1, "jwt-test 성공", null), HttpStatus.OK);
    }


    @GetMapping(path = "/message")
    public ResponseEntity<TokenDto> messageForHeader(@RequestHeader("Authorization") String access) {
        System.out.println("access = " + access);
//        System.out.println("refresh = " + refresh);
        return new ResponseEntity<>(new TokenDto(access), HttpStatus.ACCEPTED);
    }
}

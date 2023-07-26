package com.junho.oauthwithjwt.domain.user.dto;

import lombok.*;

@Data
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class TokenDto {
    private String accessToken;
    private String refreshToken;


    public TokenDto(String accessToken) {
        this.accessToken = accessToken;
    }
}

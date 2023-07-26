package com.junho.oauthwithjwt.global.handler;


import com.junho.oauthwithjwt.global.handler.ex.CustomApiException;
import com.junho.oauthwithjwt.global.handler.ex.CustomValidationApiException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ControllerExceptionHandler {

//    @ExceptionHandler(CustomValidationException.class)
//    public String validationException(CustomValidationException e) {
//
//        if (e.getErrorMap() == null) {
//            return Script.back(e.getMessage());
//        } else {
//            return Script.back(e.getErrorMap().toString());
//
//        }
//
//    }

    @ExceptionHandler(CustomValidationApiException.class)
    public ResponseEntity<?> validationApiException(CustomValidationApiException e) {


        return new ResponseEntity<>(new CMRespDto<>(-1, e.getMessage(), e.getErrorMap()), HttpStatus.BAD_REQUEST);
    }


    @ExceptionHandler(CustomApiException.class)
    public ResponseEntity<?> apiException(CustomApiException e) {
        System.out.println("나발동돼????");

        return new ResponseEntity<>(new CMRespDto<>(-1, e.getMessage(),null), HttpStatus.BAD_REQUEST);
    }
}

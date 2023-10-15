package com.superhan.springsecuritydemo.sign.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1/sign")
public class SignController {

    @PostMapping(value = "/up")
    public ResponseEntity<String> signUp(){
        return ResponseEntity.ok("회원가입 완료");
    }


    @PostMapping(value = "/in")
    public ResponseEntity<String> signIn(){
        return ResponseEntity.ok("로그인 완료");
    }

    @PostMapping(value = "/out")
    public ResponseEntity<String> signOut(){
        return ResponseEntity.ok("로그아웃");
    }
}

package com.superhan.springsecuritydemo.auth.controller;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.superhan.springsecuritydemo.auth.dto.AuthenticationRequestDto;
import com.superhan.springsecuritydemo.common.security.repository.UserRepository;
import com.superhan.springsecuritydemo.common.security.utils.JwtUtils;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

  private final AuthenticationManager authenticationManager;
  private final JwtUtils jwtUtils;
  private final UserRepository userRepository;

  @PostMapping("/authenticate")
  // @CrossOrigin("*")
  public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequestDto request)
      throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {

    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.getEmail(),
            request.getPassword()));

    final UserDetails userDetails = userRepository.findUserByEmail(request.getEmail());

    // if (userDetails != null) {
    // return ResponseEntity.ok(jwtUtils.generateToken(userDetails));
    // }
    // return ResponseEntity.status(400).body("Some error has occured");
    return ResponseEntity.ok(jwtUtils.generateToken(userDetails));
  }

  @PostMapping(value = "/sign-up")
  public ResponseEntity<String> signUp() {
    return ResponseEntity.ok("회원가입 완료");
  }

  @PostMapping(value = "/sign-in")
  public ResponseEntity<String> signIn() {
    return ResponseEntity.ok("로그인 완료");
  }

  @PostMapping(value = "/sign-out")
  public ResponseEntity<String> signOut() {
    return ResponseEntity.ok("로그아웃");
  }
}

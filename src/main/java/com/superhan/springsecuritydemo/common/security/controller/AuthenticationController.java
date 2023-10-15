package com.superhan.springsecuritydemo.common.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.superhan.springsecuritydemo.common.security.controller.dto.AuthenticationRequest;
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
  public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequest request) {

    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));

    final UserDetails userDetails = userRepository.findUserByEmail(request.getEmail());

    if (userDetails != null) {
      return ResponseEntity.ok(jwtUtils.generateToken(userDetails));
    }

    return ResponseEntity.status(400).body("Some error has occured");

  }
}

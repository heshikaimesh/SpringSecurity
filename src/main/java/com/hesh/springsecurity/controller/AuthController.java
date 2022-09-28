package com.hesh.springsecurity.controller;

import com.hesh.springsecurity.dtos.LoginRequest;
import com.hesh.springsecurity.service.AuthenticationService;
import com.hesh.springsecurity.util.JWTUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationService authenticationService;

    private final AuthenticationManager authenticationManager;

    private final JWTUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager, AuthenticationService authenticationService, JWTUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.authenticationService = authenticationService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("login")
    public String getLoginPages(@RequestBody LoginRequest loginRequest){
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),loginRequest);
        authenticationManager.authenticate(token);

        UserDetails user = authenticationService.loadUserByUsername(loginRequest.getUsername());
        return jwtUtil.generateToken(user);
    }

    @GetMapping("loginpage")
    public String testLogin(){
        return "login page works";
    }
}

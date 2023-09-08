package com.pial.springsecuritytaskauthorization.controller;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.pial.springsecuritytaskauthorization.constants.AppConstants;
import com.pial.springsecuritytaskauthorization.model.UserDto;
import com.pial.springsecuritytaskauthorization.model.UserLoginReqModel;
import com.pial.springsecuritytaskauthorization.service.UserService;
import com.pial.springsecuritytaskauthorization.service.impl.UserServiceImpl;
import com.pial.springsecuritytaskauthorization.utils.JWTUtils;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
public class UserController {

    @Autowired
    private UserServiceImpl userServiceImpl;

    @Autowired
    private AuthenticationManager authenticationManager;


    @GetMapping("/post/show")
    public String postShow(){
        return "Post Show!";
    }
    @GetMapping("/post/create")
    public String postCreate(){
        return "Post Created!";
    }

    @GetMapping("/post/delete")
    public String postDelete(){
        return "Post Deleted!";
    }

    @GetMapping("/post/edit")
    public String postEdit(){
        return "Post Edited!";
    }

    @GetMapping("/post/like")
    public String postLike(){
        return "Post Liked!";
    }

    @GetMapping("/post/comment")
    public String postComment(){
        return "Post Commented!";
    }


    @PostMapping("/users/registration")
    public ResponseEntity<?> register (@RequestBody UserDto userDto) {
        try {
            UserDto createdUser = userServiceImpl.createUser(userDto);
            String accessToken = JWTUtils.generateToken(createdUser.getEmail());
            Map<String, Object> registerResponse = new HashMap<>();
            registerResponse.put("user", createdUser);
            registerResponse.put(AppConstants.HEADER_STRING, AppConstants.TOKEN_PREFIX + accessToken);
            return ResponseEntity.status(HttpStatus.CREATED).body(registerResponse);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(),HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/users/login")
    public ResponseEntity<?> login(@RequestBody UserLoginReqModel userLoginReqModel, HttpServletResponse response) throws IOException {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userLoginReqModel.getEmail(), userLoginReqModel.getPassword()));
            if (authentication.isAuthenticated()) {
                UserDto userDto = userServiceImpl.getUser(userLoginReqModel.getEmail());
                String accessToken = JWTUtils.generateToken(userDto.getEmail());

                Map<String, Object> loginResponse = new HashMap<>();
                loginResponse.put("userId", userDto.getUserId());
                loginResponse.put("email", userDto.getEmail());
                loginResponse.put(AppConstants.HEADER_STRING, AppConstants.TOKEN_PREFIX + accessToken);
                return ResponseEntity.status(HttpStatus.OK).body(loginResponse);

            } else {
                return new ResponseEntity<>("Invalid email or password!", HttpStatus.UNAUTHORIZED);
            }
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>("Username not found!", HttpStatus.UNAUTHORIZED);

        }
    }

}

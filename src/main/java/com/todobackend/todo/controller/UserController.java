package com.todobackend.todo.controller;

import com.todobackend.todo.dto.ResponseDTO;
import com.todobackend.todo.dto.UserDTO;
import com.todobackend.todo.model.UserEntity;
import com.todobackend.todo.security.TokenProvider;
import com.todobackend.todo.service.UserService;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Log4j2
@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserService userService;

    //토큰 처리를 위한 provider를 불러옴...
    @Autowired
    private TokenProvider tokenProvider;

    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody UserDTO userDTO) {
        try {
            if(userDTO == null || userDTO.getPassword() == null){
                throw new RuntimeException("Invalid Password value.");
            }

            // 요청을 이용해서 저장할 유저 만들기
            UserEntity user = UserEntity.builder()
                    .username(userDTO.getUsername())
                    .password(passwordEncoder.encode(userDTO.getPassword()))
                    .build();
            //passwordEncoder.encode를 사용할 때 해쉬값 확인...
            log.info("생성한 사용자의 패스워드 : "+user.getPassword());
            // 서비스를 이용해서 레포지토리에 유저 저장
            UserEntity registeredUser = userService.create(user);
            //---------------------- 사용 생성....
            UserDTO responseUserDTO = UserDTO.builder()
                    .id(registeredUser.getId())
                    .username(registeredUser.getUsername())
                    .build();

            return ResponseEntity.ok().body(responseUserDTO);

        }catch (Exception e){
            // 유저 정보는 항상 하나의 결과이기 때문에 리스트로 만들어 사용한
            // responseDTO를 사용하지 않은 상태로 구현...
            // 하지만, 예외가 발생하면 그 예외에 대한 처리를 위해서 responseDTO를 사용
            ResponseDTO responseDTO = ResponseDTO.builder().error(e.getMessage()).build();
            return ResponseEntity.badRequest().body(responseDTO);
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticate(@RequestBody UserDTO userDTO) {
        UserEntity user = userService.getByCredentials(
                userDTO.getUsername(),
                userDTO.getPassword(),
                passwordEncoder
        );

        if(user != null){   //로그인 성공
            final String token = tokenProvider.create(user);
            final UserDTO responseUserDTO = UserDTO.builder()
                    .username(user.getUsername())
                    .id(user.getId())
                    .token(token)
                    .build();
            return ResponseEntity.ok().body(responseUserDTO);
        }else {             //로그인 실패
            ResponseDTO responseDTO = ResponseDTO.builder()
                    .error("Login failed").build();
            return ResponseEntity.badRequest().body(responseDTO);
        }

    }

}

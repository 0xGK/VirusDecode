package VirusDecode.backend.controller;
import VirusDecode.backend.dto.SignUpDto;
import VirusDecode.backend.dto.UserLoginDto;
import VirusDecode.backend.entity.JsonData;
import VirusDecode.backend.entity.User;
import VirusDecode.backend.service.JsonDataService;
import VirusDecode.backend.service.UserService;
import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpSession;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@RestController
@RequestMapping("/api/auth")
public class UserController {
    private final UserService userService;
    private final JsonDataService jsonDataService;

    @Autowired
    public UserController(UserService userService, JsonDataService jsonDataService){
        this.userService = userService;
        this.jsonDataService = jsonDataService;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody UserLoginDto loginDto, HttpSession session) {
        User user = userService.findUserByLoginId(loginDto.getLoginId());
        session.setMaxInactiveInterval(3600);
        if (user == null) {
            return ResponseEntity.status(401).body("유효하지 않은 ID 입니다.");
        }

        if (userService.checkPassword(user, loginDto.getPassword())) {
            session.setAttribute("userId", user.getId());
            System.out.println(user.getId());
            return ResponseEntity.ok("User logged in successfully.");
        } else {
            return ResponseEntity.status(401).body("비밀번호가 틀렸습니다.");
        }
    }
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignUpDto signupDto) {
        if (userService.findUserByLoginId(signupDto.getLoginId()) != null) {
            return ResponseEntity.status(400).body("이미 존재하는 ID 입니다.");
        }

        User newUser = userService.createUser(signupDto);
        return ResponseEntity.ok("User created successfully with ID: " + newUser.getId());
    }

    @PostMapping("/userinfo")
    public ResponseEntity<String> getUserInfo(HttpSession session) {
        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User not authenticated");
        }

        User user = userService.findUserByUserId(userId);
        if(user==null){
            return ResponseEntity.status(400).body("유저 이름을 찾을 수 없습니다.");
        }


        Map<String, String> combinedJson = new HashMap<>();
        combinedJson.put("userName", user.getFirstName());
        combinedJson.put("loginId", user.getLoginId());

        String userInfo = new Gson().toJson(combinedJson);

        return ResponseEntity.ok(userInfo);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpSession session) {
        String sessionId = session.getId();
        String uniqueLoginId = "Guest_" + sessionId.substring(0, 6);
        User existingUser = userService.findUserByLoginId(uniqueLoginId);
        if (existingUser != null) {
            jsonDataService.deleteAllHistoriesByUserId(existingUser.getId());
            userService.deleteUserById(existingUser.getId());
        }

        session.invalidate();  // 세션 무효화
        return ResponseEntity.ok("User logged out successfully.");
    }

    @PostMapping("/guest-login")
    public ResponseEntity<String> guestLogin(@RequestBody UserLoginDto loginDto, HttpSession session) {
        session.setMaxInactiveInterval(3600);
        // "virusdecode" ID로 로그인 시도 시 유저가 없으면 새로 생성
        String sessionId = session.getId();
        String uniqueLoginId = "Guest_" + sessionId.substring(0, 6);

        // uniqueLoginId가 기존에 존재하는지 확인
        User existingUser = userService.findUserByLoginId(uniqueLoginId);
        if (existingUser != null) {
            // 이미 존재하는 유저가 있으면 그 유저로 로그인 처리
            session.setAttribute("userId", existingUser.getId());
            return ResponseEntity.ok("Existing user logged in with ID: " + uniqueLoginId);
        }

        // signupDto 생성 및 LoginId에 고유한 값 설정
        SignUpDto signupDto = new SignUpDto();
        signupDto.setLoginId(uniqueLoginId);  // 세션 ID를 포함한 고유한 ID
        signupDto.setPassword("default_password");  // 기본 비밀번호 설정
        signupDto.setFirstName("Guest");
        signupDto.setLastName("Guest");

        // userService.createUser() 메서드를 사용하여 새 유저 생성
        User newUser = userService.createUser(signupDto);

        // 기존 JsonData 찾기
        Long guestUserId = userService.getUserIdByLoginId("Guest");
        List<String> guestHistoryNames = jsonDataService.getHistoryNamesByUserId(guestUserId);

        if (guestHistoryNames.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("There is no history for Guest user");
        }

        // 각 history_name에 대해 JsonData를 복사하여 새 유저로 저장
        for (String historyName : guestHistoryNames) {
            JsonData originalJsonData = jsonDataService.getJsonData(historyName, guestUserId);
            if (originalJsonData != null) {
                JsonData newJsonData = new JsonData();
                newJsonData.setHistoryName(originalJsonData.getHistoryName());
                newJsonData.setHistoryName(originalJsonData.getHistoryName());
                newJsonData.setReferenceId(originalJsonData.getReferenceId());
                newJsonData.setAlignment(originalJsonData.getAlignment());
                newJsonData.setLinearDesign(originalJsonData.getLinearDesign());
                newJsonData.setPdb(originalJsonData.getPdb());
                newJsonData.setUser(newUser);  // 새로운 유저로 설정
                // 새로운 JsonData 저장
                jsonDataService.saveJsonData(newJsonData);
            }

        }

        session.setAttribute("userId", newUser.getId());  // 새 유저의 ID를 세션에 저장
        return ResponseEntity.ok("New temporary user created and logged in with ID: " + uniqueLoginId);
    }


}

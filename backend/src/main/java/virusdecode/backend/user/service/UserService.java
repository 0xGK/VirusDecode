package virusdecode.backend.user.service;

import virusdecode.backend.user.dto.SignUpDto;
import virusdecode.backend.user.dto.UserInfoDto;
import virusdecode.backend.history.entity.History;
import virusdecode.backend.analysis.entity.Analysis;
import virusdecode.backend.user.entity.User;
import virusdecode.backend.user.exception.DuplicateLoginIdException;
import virusdecode.backend.user.exception.InvalidLoginException;
import virusdecode.backend.user.exception.UserNotFoundException;
import virusdecode.backend.user.repository.UserRepository;
import virusdecode.backend.history.service.HistoryService;
import virusdecode.backend.analysis.service.AnalysisService;
import jakarta.transaction.Transactional;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

@Log4j2
@Service
public class UserService {
    private final AnalysisService analysisService;
    private final HistoryService historyService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(AnalysisService analysisService, HistoryService historyService,
                       UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.analysisService = analysisService;
        this.historyService = historyService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public UserInfoDto login(String loginId, String password){
        User user = findUserByLoginId(loginId);
        if (user==null || !checkPassword(user, password)) {
            throw new InvalidLoginException("등록되지 않는 회원 정보입니다.");
        }
        return new UserInfoDto(user.getLoginId(), user.getFirstName());
    }

    public UserInfoDto fetchUserInfo(Long userId){
        User user = getUserById(userId);
        return new UserInfoDto(user.getLoginId(), user.getFirstName());
    }

    public User findUserByLoginId(String loginId) {

        return userRepository.findByLoginId(loginId);
    }



    @Transactional
    public User createUser(SignUpDto signUpDto, String role) {
        String loginId = signUpDto.getLoginId();
        if (findUserByLoginId(loginId) != null) {
            throw new DuplicateLoginIdException("이미 존재하는 ID 입니다.");
        }

        User newUser = new User(signUpDto.getFirstName(), signUpDto.getLastName(), signUpDto.getLoginId(), passwordEncoder.encode(signUpDto.getPassword()), role);
        userRepository.save(newUser);
        copySampleHistoriesToNewUser(newUser);
        return newUser;
    }


    public boolean checkPassword(User user, String password) {
        return passwordEncoder.matches(password, user.getPassword());
    }

    // userId로 유저 객체를 반환
    public User getUserById(Long userId) {
        Optional<User> userOptional = userRepository.findById(userId);
        if(userOptional.isPresent()){
            return userOptional.get();
        }else{
            throw new UserNotFoundException("유저를 찾을 수 없습니다.");
        }
    }

    public Long getUserIdByLoginId(String loginId) {
        User user = userRepository.findByLoginId(loginId);
        return user != null ? user.getId() : null;  // user가 있으면 userId 반환, 없으면 null 반환
    }


    /*
        ┌───────────── 초 (0 - 59)
        │ ┌───────────── 분 (0 - 59)
        │ │ ┌───────────── 시간 (0 - 23)
        │ │ │ ┌───────────── 일 (1 - 31)
        │ │ │ │ ┌───────────── 월 (1 - 12)
        │ │ │ │ │ ┌───────────── 요일 (0 - 7) (일요일=0 또는 7)
        │ │ │ │ │ │
        * * * * * *
     */
//    @Scheduled(cron = "0 */5 * * * ?")  // 5분마다 실행
    @Scheduled(cron = "0 0 3 * * ?")  // 매일 오전 3시에 실행
    @Transactional
    public void deleteGuestUsers() {
        List<User> guestUsers = userRepository.findUsersByRole("GUEST");
        int guest_cnt = 0;
        for (User user : guestUsers) {
            if (user.getCreatedAt().isBefore(LocalDateTime.now().minus(24, ChronoUnit.HOURS))) {
                guest_cnt++;
                Long userId = user.getId();
                List<String> historyList = historyService.getHistoryNamesByUserId(userId);
                for(String historyName : historyList){
                    History history = historyService.getHistory(historyName, userId);
                    analysisService.deleteAnalysisData(history);
                    historyService.deleteHistory(historyName, userId);
                }
                userRepository.deleteUserById(user.getId());
            }
        }

        if (guest_cnt > 0) {
            log.info("Deleted {} GUEST users who were created more than 24 hours ago.", guest_cnt);
        }
    }

    public void copySampleHistoriesToNewUser(User newUser) {
        Long guestUserId = getUserIdByLoginId("Guest");
        List<String> guestHistoryNames = historyService.getHistoryNamesByUserId(guestUserId);

        for (String historyName : guestHistoryNames) {
            History history = historyService.getHistory(historyName, guestUserId);
            if (history != null) {
                Analysis originalAnalysis = analysisService.getAnalysisData(history);
                if (originalAnalysis != null) {
                    History newHistory = new History();
                    newHistory.setHistoryName(historyName);
                    newHistory.setUser(newUser);
                    historyService.createHistory(newHistory);

                    Analysis newAnalysis = new Analysis();
                    newAnalysis.setReferenceId(originalAnalysis.getReferenceId());
                    newAnalysis.setAlignment(originalAnalysis.getAlignment());
                    newAnalysis.setLinearDesign(originalAnalysis.getLinearDesign());
                    newAnalysis.setPdb(originalAnalysis.getPdb());
                    newAnalysis.setHistory(newHistory);
                    analysisService.saveAnalysisData(newAnalysis);
                }
            }
        }
    }
}

package com.example.security_log_system.service;


import com.example.security_log_system.entity.AdminUser;
import com.example.security_log_system.repository.AdminUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Component
@Profile("local")
@ConditionalOnProperty(
        name = "app.bootstrap-admin.enabled",
        havingValue = "true"
)
@RequiredArgsConstructor
public class LocalAdminInitializer implements ApplicationRunner {

    private final AdminUserRepository adminUserRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.bootstrap-admin.username:}")
    private String username;

    @Value("${app.bootstrap-admin.password:}")
    private String password;

    @Override
    @Transactional
    public void run(ApplicationArguments args){
        if(username.isBlank() || username.length() > 50){
            throw new IllegalStateException("초기 관리자 아이디는 1~50자로 설정해야 합니다.");
        }

        // 기존 계정의 비밀번호나 권한은 변경하지 않음
        if(adminUserRepository.findByUsername(username).isPresent()){
            log.info("동일한 아이디가 존재하여 초기 관리자 생성을 생략합니다.");
            return;
        }

        if(password.isBlank()){
            throw new IllegalStateException("초기 관리자 비밀번호를 설정해야 합니다.");
        }

        AdminUser admin = AdminUser.builder()
                .username(username)
                .password(passwordEncoder.encode(password))
                .role("ROLE_ADMIN")
                .build();

        adminUserRepository.saveAndFlush(admin);

        log.info("로컬 초기 관리자 계정을 생성했습니다.");
    }
}

/*
    local 프로필인가?
        → 초기화 옵션이 true인가?
            → 같은 아이디가 없으면
                → 비밀번호를 BCrypt로 해시
                → 관리자 계정 저장
* */
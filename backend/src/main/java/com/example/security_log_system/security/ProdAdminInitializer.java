package com.example.security_log_system.security;


import com.example.security_log_system.entity.AdminUser;
import com.example.security_log_system.repository.AdminUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@Profile("prod")
@ConditionalOnProperty(
        name = "app.bootstrap-admin.enabled",
        havingValue = "true",
        matchIfMissing = false
)
@RequiredArgsConstructor
public class ProdAdminInitializer implements ApplicationRunner {

    private static final String ADMIN_ROLE = "ROLE_ADMIN";

    private final AdminUserRepository adminUserRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.bootstrap-admin.username:}")
    private String username;

    @Value("${app.bootstrap-admin.password:}")
    private String password;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {

        // 기존 관리자가 있으면 계정 추가나 비밀번호 변경 없이 종료
        if(adminUserRepository.existsByRole(ADMIN_ROLE)){
            log.info("기존 관리자가 있어 운영 초기 관리자 생성을 생략합니다.");
            return;
        }

        String normalizedUsername = username.trim();

        validateCredentials(normalizedUsername);

        // 같은 아이디의 다른 계정을 관리자로 승격시키지 않음
        if(adminUserRepository.findByUsername(normalizedUsername).isPresent()){
            throw new IllegalStateException("초기 관리자 아이디가 기존 계정과 중복됩니다.");
        }

        AdminUser admin = AdminUser.builder()
                .username(normalizedUsername)
                .password(passwordEncoder.encode(password))
                .role(ADMIN_ROLE)
                .build();

        adminUserRepository.saveAndFlush(admin);

        // 비밀번호와 해시 값은 로그에 출력하지 않음
        log.info("운영 초기 관리자 계정 생성을 완료했습니다.");
    }

    private void validateCredentials(String normalizedUsername){
        if(normalizedUsername.isBlank()
        || normalizedUsername.length() > 50){
            throw new IllegalStateException("초기 관리자 아이디는 1~50자로 설정해야 합니다.");
        }

        int passwordLength = password.codePointCount(0,password.length());

        if(password.isBlank() || passwordLength < 8){
            throw new IllegalStateException("초기 관리자 비밀번호는 8자 이상으로 설정해야합니다.");
        }

        // 현재 프로젝트의 BCrypt 인코더 입력 제한
        if(password.getBytes(StandardCharsets.UTF_8).length > 72){
                throw new IllegalStateException("초기 관리자 비밀번호는 UTF-8 기준 72바이트 이하여야 합니다.");
        }


    }


}

package com.example.security_log_system.repository;

import com.example.security_log_system.entity.AdminUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

// JpaRepository<AdminUser, Long> -> AdminUser 테이블을 다루고, PK타입은 Long
public interface AdminUserRepository extends JpaRepository<AdminUser, Long> {
    // Optional -> 결과가 없을 수도 있으니 null 대신 Optional로 감싸서 반환
    Optional<AdminUser> findByUsername(String username);

    // 해당 역할을 가진 계정이 하나라도 있는지 확인
    boolean existsByRole(String role);
}


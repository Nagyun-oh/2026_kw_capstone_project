package com.example.security_log_system.repository;

import com.example.security_log_system.entity.WafDetection;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface WafDetectionRepository extends JpaRepository<WafDetection,Long> {

    boolean existsByRequestId(String requestId);

    Optional<WafDetection> findByDetectedThreat_Id(Long threatId);

    Optional<WafDetection> findByRequestId(String requestId);
}

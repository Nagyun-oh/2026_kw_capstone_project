package com.example.security_log_system.repository;

import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.LogEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;

/* 탐지된 위협 데이터를 저장하고 조회하는 용도입니다. */
@Repository
public interface ThreatRepository
        extends JpaRepository<DetectedThreat,Long>,
        JpaSpecificationExecutor<DetectedThreat> {
    boolean existsByLogEntry_IdAndThreatType(Long logId, String threatType);

}

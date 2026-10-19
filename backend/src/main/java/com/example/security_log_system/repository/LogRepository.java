package com.example.security_log_system.repository;

import com.example.security_log_system.entity.LogEntry;
import lombok.extern.java.Log;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.Optional;


/*  전체 방문 기록(로그) 관리*/
public interface LogRepository
        extends JpaRepository<LogEntry,Long>,
                JpaSpecificationExecutor<LogEntry> {

    Optional<LogEntry> findByRequestId(String requestId);
}


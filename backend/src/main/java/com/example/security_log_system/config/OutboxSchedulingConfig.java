package com.example.security_log_system.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

@Configuration
public class OutboxSchedulingConfig {

    // 기존 알림·보고 스케줄러가 사용하는 기본 실행기
    @Bean(name = "taskScheduler")
    public ThreadPoolTaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler =
                new ThreadPoolTaskScheduler();

        scheduler.setPoolSize(1);
        scheduler.setThreadNamePrefix("app-scheduler-");

        return scheduler;
    }

    // Kafka 대기가 기존 알림 스케줄러를 막지 않도록 분리
    @Bean(name = "aiRequestOutboxScheduler")
    public ThreadPoolTaskScheduler aiRequestOutboxScheduler() {
        ThreadPoolTaskScheduler scheduler =
                new ThreadPoolTaskScheduler();

        scheduler.setPoolSize(1);
        scheduler.setThreadNamePrefix("ai-outbox-");

        return scheduler;
    }
}
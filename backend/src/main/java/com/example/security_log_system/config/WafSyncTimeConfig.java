package com.example.security_log_system.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/* WAF 보고 체계에서 테스트 가능한 시계 설정*/
@Configuration
public class WafSyncTimeConfig {

    @Bean
    public Clock wafSyncClock(){
        return Clock.systemUTC();
    }
}

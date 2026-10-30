package com.example.security_log_system.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;


/* RestTemplate, Async/Scheduling 활성화 클래스 */

@Configuration      // Spring 설정 클래스
@EnableAsync        // 비동기 메서드 실행 활성화
@EnableScheduling   // 스케줄러 기능 활성화
public class WebConfig  {

    // RestTemplate은 Spring에서 외부 HTTP API를 호출할 때 사용한다.
    @Bean
    public RestTemplate restTemplate(){
        return new RestTemplate();
    }

}

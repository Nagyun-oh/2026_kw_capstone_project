package com.example.security_log_system.scheduler;


import com.example.security_log_system.repository.ThreatRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ReportScheduler {
    private final ThreatRepository threatRepository;

    // 테스트용: 1분마다 실행하여 작동 확인
    @Scheduled(cron = "0 * * * * *")
    public void generateReport(){
        long totalThreats = threatRepository.count();
        System.out.println("📊 [정기 리포트] 현재 시스템에 기록된 누적 위협 건수: " + totalThreats + "건");
        // 리액트에서 보여줄 통계 테이블을 업데이트하거나 메일을 발송하는 로직이 들어갑니다.
    }
}

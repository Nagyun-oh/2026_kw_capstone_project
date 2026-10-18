package com.example.security_log_system.service;


import com.example.security_log_system.repository.RequestAlertRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

// 미전송 기록을 주기적으로 읽는 전송기
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(
        name = "app.alerts.enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class RequestAlertDispatcher {

    private final RequestAlertRepository requestAlertRepository;
    private final RequestAlertPublisher requestAlertPublisher;

    @Scheduled(
            fixedDelayString = "${app.alerts.poll-delay-ms:1000}",
            initialDelayString = "${app.alerts.initial-delay-ms:5000}"
    )
    public void dispatch(){
        for(String alertKey : requestAlertRepository.findPendingKeys()){
            try{
                requestAlertPublisher.publish(alertKey);
            } catch(Exception exception){
                log.warn("Request alert dispatch failed; will retry. key={}",
                        alertKey,
                        exception);
            }
        }
    }
}

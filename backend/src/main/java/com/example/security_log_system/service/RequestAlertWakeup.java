package com.example.security_log_system.service;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.stereotype.Component;

/**
 * 요청 알림이 새로 발행 대기 상태가 되면 알림 발행기를 바로 실행한다.
 * 알림 발행기의 @Scheduled가 쓰는 기본 taskScheduler(스레드 1개)에 넣으므로 주기 실행과 겹치지 않는다.
 * app.alerts.enabled=false라 발행기가 없으면 아무것도 하지 않는다.
 */
@Component
public class RequestAlertWakeup extends AfterCommitDispatchTrigger {

    public RequestAlertWakeup(
            @Qualifier("taskScheduler") ThreadPoolTaskScheduler scheduler,
            ObjectProvider<RequestAlertDispatcher> dispatcher,
            @Value("${app.alerts.wakeup-enabled:true}") boolean enabled
    ) {
        super(
                "request-alert",
                scheduler,
                () -> {
                    RequestAlertDispatcher current = dispatcher.getIfAvailable();
                    return current == null ? null : current::dispatch;
                },
                enabled
        );
    }
}

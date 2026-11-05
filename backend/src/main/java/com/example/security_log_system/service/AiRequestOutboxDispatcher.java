package com.example.security_log_system.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;


// 주기적으로 호출하는 Dispatcher
// - 한 번에 최대 20개를 처리하고, 작업이 없거나 발행이 실패하면 이번 주기를 끝냄
// - 실패한 요청을 삭제하거나 성공으로 처리하지 않음
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(
        name = "app.ai-outbox.enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class AiRequestOutboxDispatcher {

    private final AiRequestOutboxPublisher publisher;

    @Scheduled(
            scheduler = "aiRequestOutboxScheduler",
            fixedDelayString = "${app.ai-outbox.poll-delay-ms:500}",
            initialDelayString = "${app.ai-outbox.initial-delay-ms:5000}"
    )
    public void dispatch() {
        for (int i = 0; i < 20; i++) {
            try {
                if (!publisher.publishNext()) {
                    return;
                }
            } catch (Exception exception) {
                // DB 오류 등으로 완료 처리를 못 해도
                // 저장된 작업과 선점 만료를 통해 복구한다.
                log.warn(
                        "AI outbox dispatch failed. code={}",
                        exception.getClass().getSimpleName()
                );

                return;
            }
        }
    }
}
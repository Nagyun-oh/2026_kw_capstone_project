package com.example.security_log_system.service;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;
import org.springframework.stereotype.Component;

/**
 * AI 요청 outbox 행이 커밋되면 AI outbox 발행기를 바로 실행한다.
 * 발행기와 같은 aiRequestOutboxScheduler(스레드 1개)를 쓰므로 주기 실행과 겹치지 않는다.
 * 발행기는 ObjectProvider로 실행 시점에 찾는다. 생성 시점 순환 참조
 * (outbox 서비스 → 깨우기 → 발행기 → 발행 처리 → outbox 서비스)를 피하고,
 * app.ai-outbox.enabled=false라 발행기가 없으면 아무것도 하지 않는다.
 */
@Component
public class AiRequestOutboxWakeup extends AfterCommitDispatchTrigger {

    public AiRequestOutboxWakeup(
            @Qualifier("aiRequestOutboxScheduler") ThreadPoolTaskScheduler scheduler,
            ObjectProvider<AiRequestOutboxDispatcher> dispatcher,
            @Value("${app.ai-outbox.wakeup-enabled:true}") boolean enabled
    ) {
        super(
                "ai-outbox",
                scheduler,
                () -> {
                    AiRequestOutboxDispatcher current = dispatcher.getIfAvailable();
                    return current == null ? null : current::dispatch;
                },
                enabled
        );
    }
}

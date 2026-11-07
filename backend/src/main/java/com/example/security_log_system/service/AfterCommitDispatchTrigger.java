package com.example.security_log_system.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * 발행 대기 행을 저장한 트랜잭션이 커밋되면 발행기를 한 번 바로 실행하도록 예약한다.
 *
 * <ul>
 *   <li>커밋 전에는 실행하지 않는다. 롤백되면 아무것도 예약하지 않는다.</li>
 *   <li>발행기 전용 단일 스레드 실행기에 넣으므로 주기 실행(@Scheduled)과 동시에 돌지 않는다.</li>
 *   <li>이미 예약된 실행이 있으면 추가 예약하지 않는다. 실행이 시작되면 예약 표시를 먼저 지워
 *       실행 중에 커밋된 행도 다음 실행에서 처리한다.</li>
 *   <li>예약·실행이 실패해도 예외를 던지지 않는다. 기존 주기 조회가 복구 경로로 남아 있다.</li>
 * </ul>
 */
@Slf4j
public class AfterCommitDispatchTrigger {

    private final String name;
    private final Executor executor;
    private final Supplier<Runnable> dispatch;
    private final boolean enabled;
    private final AtomicBoolean queued = new AtomicBoolean(false);

    protected AfterCommitDispatchTrigger(
            String name,
            Executor executor,
            Supplier<Runnable> dispatch,
            boolean enabled
    ) {
        this.name = name;
        this.executor = executor;
        this.dispatch = dispatch;
        this.enabled = enabled;
    }

    /** 현재 트랜잭션이 커밋된 뒤 발행기를 깨운다. 저장과 같은 트랜잭션 안에서 호출한다. */
    public void requestAfterCommit() {
        if (!enabled) {
            return;
        }

        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            // 커밋 시점을 알 수 없으면 깨우지 않는다. 주기 조회가 처리한다.
            return;
        }

        TransactionSynchronizationManager.registerSynchronization(
                new TransactionSynchronization() {
                    @Override
                    public void afterCommit() {
                        signal();
                    }
                }
        );
    }

    /** 커밋 이후 호출된다. Kafka Consumer 스레드를 막지 않도록 예약만 하고 바로 반환한다. */
    void signal() {
        Runnable task = dispatch.get();

        if (task == null) {
            // 발행기가 비활성화된 환경
            return;
        }

        if (!queued.compareAndSet(false, true)) {
            // 아직 시작하지 않은 실행이 있으면 그 실행이 새 행도 처리한다.
            return;
        }

        try {
            executor.execute(() -> {
                // 실행 시작 전에 표시를 지운다. 이후 커밋은 새 실행을 예약할 수 있다.
                queued.set(false);

                try {
                    task.run();
                } catch (RuntimeException exception) {
                    log.warn(
                            "After-commit dispatch failed; periodic polling will retry. dispatcher={}, code={}",
                            name,
                            exception.getClass().getSimpleName()
                    );
                }
            });
        } catch (RuntimeException exception) {
            // 종료 중 등으로 예약이 거부되면 다음 커밋이나 주기 조회가 처리한다.
            queued.set(false);
            log.warn(
                    "After-commit dispatch was not scheduled. dispatcher={}, code={}",
                    name,
                    exception.getClass().getSimpleName()
            );
        }
    }
}

package com.example.security_log_system.service;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class AfterCommitDispatchTriggerTest {

    /** 예약된 작업을 바로 실행하지 않고 모아 두는 실행기. 테스트가 실행 시점을 정한다. */
    static class QueueExecutor implements Executor {
        final List<Runnable> tasks = new ArrayList<>();

        @Override
        public void execute(Runnable command) {
            tasks.add(command);
        }

        void runAll() {
            List<Runnable> current = new ArrayList<>(tasks);
            tasks.clear();
            current.forEach(Runnable::run);
        }
    }

    private final QueueExecutor executor = new QueueExecutor();
    private final AtomicInteger dispatched = new AtomicInteger();

    private AfterCommitDispatchTrigger trigger(boolean enabled) {
        return new AfterCommitDispatchTrigger("test", executor, () -> dispatched::incrementAndGet, enabled);
    }

    @AfterEach
    void clearSynchronization() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.clearSynchronization();
        }
    }

    private void commit() {
        List<TransactionSynchronization> synchronizations =
                TransactionSynchronizationManager.getSynchronizations();
        synchronizations.forEach(TransactionSynchronization::afterCommit);
        TransactionSynchronizationManager.clearSynchronization();
    }

    @Test
    @DisplayName("커밋 전에는 실행하지 않고, 커밋된 뒤 발행기를 한 번 예약한다")
    void schedulesOnlyAfterCommit() {
        AfterCommitDispatchTrigger trigger = trigger(true);
        TransactionSynchronizationManager.initSynchronization();

        trigger.requestAfterCommit();
        assertThat(executor.tasks).isEmpty();

        commit();
        assertThat(executor.tasks).hasSize(1);

        executor.runAll();
        assertThat(dispatched).hasValue(1);
    }

    @Test
    @DisplayName("롤백되면 발행기를 예약하지 않는다")
    void rollbackDoesNotSchedule() {
        AfterCommitDispatchTrigger trigger = trigger(true);
        TransactionSynchronizationManager.initSynchronization();

        trigger.requestAfterCommit();
        TransactionSynchronizationManager.getSynchronizations()
                .forEach(s -> s.afterCompletion(TransactionSynchronization.STATUS_ROLLED_BACK));
        TransactionSynchronizationManager.clearSynchronization();

        assertThat(executor.tasks).isEmpty();
    }

    @Test
    @DisplayName("트랜잭션 동기화가 없으면 깨우지 않고 주기 조회에 맡긴다")
    void withoutTransactionDoesNothing() {
        trigger(true).requestAfterCommit();

        assertThat(executor.tasks).isEmpty();
    }

    @Test
    @DisplayName("아직 시작하지 않은 실행이 있으면 추가 예약하지 않는다")
    void coalescesWhileQueued() {
        AfterCommitDispatchTrigger trigger = trigger(true);

        trigger.signal();
        trigger.signal();
        trigger.signal();

        assertThat(executor.tasks).hasSize(1);
        executor.runAll();
        assertThat(dispatched).hasValue(1);
    }

    @Test
    @DisplayName("실행이 시작된 뒤 들어온 커밋은 다음 실행을 다시 예약한다")
    void commitDuringRunSchedulesAnotherRun() {
        AtomicInteger runs = new AtomicInteger();
        AfterCommitDispatchTrigger[] holder = new AfterCommitDispatchTrigger[1];
        // 첫 실행 도중 새 커밋이 들어온 상황을 흉내 낸다.
        holder[0] = new AfterCommitDispatchTrigger("test", executor, () -> () -> {
            if (runs.incrementAndGet() == 1) {
                holder[0].signal();
            }
        }, true);

        holder[0].signal();
        executor.runAll();

        assertThat(runs).hasValue(1);
        assertThat(executor.tasks).as("실행 중 커밋을 놓치지 않는다").hasSize(1);

        executor.runAll();
        assertThat(runs).hasValue(2);
    }

    @Test
    @DisplayName("설정으로 끄거나 발행기가 없으면 아무것도 예약하지 않는다")
    void disabledOrMissingDispatcherDoesNothing() {
        TransactionSynchronizationManager.initSynchronization();
        trigger(false).requestAfterCommit();
        assertThat(TransactionSynchronizationManager.getSynchronizations()).isEmpty();
        TransactionSynchronizationManager.clearSynchronization();

        new AfterCommitDispatchTrigger("test", executor, () -> null, true).signal();
        assertThat(executor.tasks).isEmpty();
    }

    @Test
    @DisplayName("예약이 거부돼도 예외를 던지지 않고 다음 신호에서 다시 예약할 수 있다")
    void rejectedScheduleIsContained() {
        AtomicInteger attempts = new AtomicInteger();
        Executor rejecting = command -> {
            if (attempts.incrementAndGet() == 1) {
                throw new TaskRejectedException("shutting down");
            }
            executor.execute(command);
        };
        AfterCommitDispatchTrigger trigger =
                new AfterCommitDispatchTrigger("test", rejecting, () -> dispatched::incrementAndGet, true);

        assertThatCode(trigger::signal).doesNotThrowAnyException();
        trigger.signal();

        assertThat(executor.tasks).hasSize(1);
    }

    @Test
    @DisplayName("발행기 실행 중 예외가 나도 실행 스레드로 퍼지지 않고 다음 신호를 받는다")
    void dispatchFailureIsContained() {
        AfterCommitDispatchTrigger trigger = new AfterCommitDispatchTrigger("test", executor, () -> () -> {
            throw new IllegalStateException("db down");
        }, true);

        trigger.signal();
        assertThatCode(executor::runAll).doesNotThrowAnyException();

        trigger.signal();
        assertThat(executor.tasks).hasSize(1);
    }
}

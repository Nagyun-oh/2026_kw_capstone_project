package com.example.security_log_system.service;


import com.example.security_log_system.dto.AiRequestDto;
import com.example.security_log_system.repository.AiRequestOutboxRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AiRequestOutboxService {

    private final AiRequestOutboxRepository repository;
    private final ObjectMapper objectMapper;
    private final AiRequestOutboxWakeup wakeup;

    public record Job(
            long logId,
            String payload,
            String leaseToken,
            long attempts
    ){}

    // LogEntry 저장 트랜잭션에 참여
    @Transactional(propagation = Propagation.MANDATORY)
    public void enqueue(AiRequestDto request){
        if(request == null
            || request.getLogId() == null
            || request.getLogId() <=0){
            throw new IllegalArgumentException("AI outbox requires a valid logId");
        }

        try{
            String payload = objectMapper.writeValueAsString(request);

            repository.insert(request.getLogId(),payload);

            // 로그 저장 트랜잭션이 커밋된 뒤 발행기를 바로 깨운다.
            // 롤백되면 깨우지 않고, 깨우기에 실패해도 주기 조회가 이 행을 처리한다.
            wakeup.requestAfterCommit();
        }catch (JsonProcessingException exception){
            throw new IllegalStateException("AI request seralization failed",exception);
        }
    }


    // 작업 선점만 하고 커밋
    @Transactional(
            propagation = Propagation.REQUIRES_NEW,
            isolation = Isolation.READ_COMMITTED
    )
    public Optional<Job> claimNext(){
        Optional<AiRequestOutboxRepository.Candidate> candidate =
                repository.findReadyForUpdate();

        if(candidate.isEmpty()){
            return Optional.empty();
        }

        AiRequestOutboxRepository.Candidate row =
                candidate.get();

        String leaseToken = UUID.randomUUID().toString();

        requireOne(repository.claim(row.logId(),leaseToken));

        return Optional.of(new Job(
                row.logId(),
                row.payload(),
                leaseToken,
                row.attempts()+1
        ));
    }

    // Kafka 성공 후 별도 완료 처리
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markSent(Job job){
        requireOne(repository.markSent(job.logId,job.leaseToken()));
    }


    // 실패 후 별도 재시도 예약
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void retry(Job job, String errorCode) {
        // 5초, 10초, ... 최대 60초 간격으로 재시도한다.
        int delaySeconds = (int) (
                Math.min(job.attempts(), 12L) * 5L
        );

        String safeCode = errorCode == null
                ? "UNKNOWN"
                : errorCode.substring(
                0,
                Math.min(errorCode.length(), 100)
        );

        requireOne(repository.scheduleRetry(
                job.logId(),
                job.leaseToken(),
                delaySeconds,
                safeCode
        ));
    }


    private void requireOne(int updated){
        if(updated != 1){
            throw new IllegalStateException("AI outbox ownership changed");
        }
    }


}

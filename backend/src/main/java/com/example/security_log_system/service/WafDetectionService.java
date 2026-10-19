package com.example.security_log_system.service;


import com.example.security_log_system.dto.WafDetectionEventDto;
import com.example.security_log_system.repository.WafDetectionRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class WafDetectionService implements WafDetectionHandler{

    private final WafDetectionRepository wafDetectionRepository;
    private final WafDetectionWriter wafDetectionWriter;

    // 여기에 @Transcactional을 붙이지 않음.
    // Writer의 트랜잭션이 롤백된 이후 중복 여부를 다시 확인해야 한다.
    @Override
    public void handle(WafDetectionEventDto event){
        String requestId = event.getRequestId();

        // 일반적인 재전송은 INSERT 없이 종료한다.
        if(wafDetectionRepository.existsByRequestId(requestId)) {
            log.debug("Previously stored WAF event skipped.");
            return;
        }

        try{
            wafDetectionWriter.saveNewDetection(event);
        } catch (DataIntegrityViolationException exception){
            // 동시에 같은 요청을 처리하면 위의 exists 결과는 양쪽 모두 false일 수 있다.
            //
             // Writer가 롤백된 뒤, 다른 처리에서 저장했는지 확인한다.
            if(wafDetectionRepository.existsByRequestId(requestId)){
                log.debug("Concurrently stored WAF event skipped.");
                return;
            }

            // 해당 요청이 실제로 저장되지 않았다면
            // 중복으로 간주하지 않고 오류를 전파한다.
            throw exception;
        }

    }



}

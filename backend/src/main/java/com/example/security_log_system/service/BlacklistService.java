package com.example.security_log_system.service;

import com.example.security_log_system.dto.BlacklistResponseDto;
import com.example.security_log_system.dto.BlacklistSearchCondition;
import com.example.security_log_system.entity.DetectedThreat;
import com.example.security_log_system.entity.IpBlacklist;
import com.example.security_log_system.repository.BlacklistRepository;
import com.example.security_log_system.repository.BlacklistSpecification;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.example.security_log_system.util.UtcDateTime;

import java.time.LocalDateTime;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class BlacklistService {

    private final BlacklistRepository blacklistRepository;
    private final MeterRegistry meterRegistry;

    // GET
    @Transactional(readOnly = true)
    public Page<BlacklistResponseDto> getBlacklists(BlacklistSearchCondition condition, Pageable pageable){
        return blacklistRepository.findAll(BlacklistSpecification.search(condition),pageable)
                .map(BlacklistResponseDto::from);
    }

    // 수동 블랙리스트 등록: 원인이 된 위협 x (ex. swaager ui를 통한 등록)
    public boolean addToBlacklist(String ip, String reason, int dangerLevel){
        return addToBlacklist(ip,reason,dangerLevel,null);
    }


    // 위협으로 인한 블랙리스트 등록
    public boolean addToBlacklist(String ip, String reason, int dangerLevel, DetectedThreat sourceThreat){

        // 블랙리스트에 해당 ip가 이미 존재하면, 등록하지 않는다.
        if(isBlocked(ip)){
            log.info("Blacklist registration skipped: IP already exists");
            return false;
        }

        IpBlacklist blacklist = IpBlacklist.builder()
                .sourceThreat(sourceThreat)
                .ipAddress(ip)
                .reason(reason)
                .dangerLevel(dangerLevel)
                .createdAt(UtcDateTime.now())
                .build();

        blacklistRepository.save(blacklist);

        // 등록 성공 시 Counter 증가
        Counter.builder("security.blacklist.registrations")
                .description("Number of IP addresses added to blacklist")
                .register(meterRegistry)
                .increment();

        return true;
    }

    // DELETE
    public boolean deleteBlacklist(Long id){
        if(!blacklistRepository.existsById(id)){
            return false;
        }

        blacklistRepository.deleteById(id);
        return true;
    }

    @Transactional(readOnly = true)
    public boolean isBlocked(String ipAddress){
        return blacklistRepository.findByIpAddress(ipAddress).isPresent();
    }

}
package com.example.security_log_system.service;

import com.example.security_log_system.dto.BlacklistResponseDto;
import com.example.security_log_system.dto.BlacklistSearchCondition;
import com.example.security_log_system.entity.IpBlacklist;
import com.example.security_log_system.repository.BlacklistRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class BlacklistServiceTest {

    @Mock
    private BlacklistRepository blacklistRepository;

    private MeterRegistry meterRegistry = new SimpleMeterRegistry();

    private BlacklistService blacklistService;

    @BeforeEach
    void setUp(){
        blacklistService = new BlacklistService(blacklistRepository,meterRegistry);
    }

    @Test
    @DisplayName("검색 조건으로 블랙리스트를 조회하고 Entity Page를 DTO Page로 변환한다")
    void getAllBlacklists_thenReturnDtoPage(){

        // given
        BlacklistSearchCondition condition = new BlacklistSearchCondition();
        condition.setIp("192.168.0.10");
        condition.setDangerLevel(4);

        Pageable pageable = PageRequest.of(0,20);

        IpBlacklist blacklist = IpBlacklist.builder()
                .id(1L)
                .ipAddress("192.168.0.10")
                .reason("Repeated Attack")
                .dangerLevel(4)
                .createdAt(LocalDateTime.now())
                .build();

        Page<IpBlacklist> page = new PageImpl<>(List.of(blacklist),pageable,1);

        // when
        when(blacklistRepository.findAll(
                any(Specification.class),
                eq(pageable)
        )).thenReturn(page);

        Page<BlacklistResponseDto> result = blacklistService.getBlacklists(condition,pageable);

        // then
        assertThat(result.getTotalElements()).isEqualTo(1);
        assertThat(result.getContent().get(0).getIpAddress()).isEqualTo("192.168.0.10");
        assertThat(result.getContent().get(0).getReason()).isEqualTo("Repeated Attack");
        assertThat(result.getContent().get(0).getDangerLevel()).isEqualTo(4);

        verify(blacklistRepository).findAll(
                any(Specification.class),
                eq(pageable)
        );

    }

    @Test
    @DisplayName("새 IP 등록 성공 시 save 호출 후 true 반환")
    void addToBlacklist_whenIpNotExists_thenSaveAndReturnTrue(){

        // when
        when(blacklistRepository.findByIpAddress("192.168.0.10"))
                .thenReturn(Optional.empty());

        // given
        boolean result = blacklistService.addToBlacklist(
                "192.168.0.10",
                "Repeated attack",
                4
        );

        ArgumentCaptor<IpBlacklist> captor = ArgumentCaptor.forClass(IpBlacklist.class);

        verify(blacklistRepository).save(captor.capture());

        IpBlacklist saved = captor.getValue();

        // then
        assertThat(result).isTrue();
        assertThat(saved.getIpAddress()).isEqualTo("192.168.0.10");
        assertThat(saved.getReason()).isEqualTo("Repeated attack");
        assertThat(saved.getDangerLevel()).isEqualTo(4);
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(meterRegistry.counter("security.blacklist.registrations").count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("중복 IP 등록 시 save 하지 않고 false 반환")
    void addToBlacklist_whenIpAlreadyExists_thenReturnFalse(){

        // given
        IpBlacklist existing = IpBlacklist.builder()
                .id(1L)
                .ipAddress("192.168.0.10")
                .build();

        // when
        when(blacklistRepository.findByIpAddress("192.168.0.10"))
                .thenReturn(Optional.of(existing));

        boolean result = blacklistService.addToBlacklist(
                "192.168.0.10",
                "Repeated attack",
                4
        );

        // then
        assertThat(result).isFalse();
        verify(blacklistRepository,never()).save(any());
    }

    @Test
    @DisplayName("삭제 대상이 존재하면 deleteById 호출 후 true 반환")
    void deleteBlacklist_whenIdExists_thenDeleteAndReturnTrue(){

        // when
        when(blacklistRepository.existsById(1L)).thenReturn(true);

        // given
        boolean result = blacklistService.deleteBlacklist(1L);

        // then
        assertThat(result).isTrue();
        verify(blacklistRepository).deleteById(1L);
    }

    @Test
    @DisplayName("삭제 대상이 없으면 deleteById 호출하지 않고 false 반환")
    void deleteBlacklist_whenIdNotExists_thenReturnFalse(){

        // when
        when(blacklistRepository.existsById(1L)).thenReturn(false);

        // given
        boolean result = blacklistService.deleteBlacklist(1L);

        // then
        assertThat(result).isFalse();
        verify(blacklistRepository,never()).deleteById(any());
    }

    @Test
    @DisplayName("블랙리스트 DB에 등록되어있으면, True를 반환한다.")
    void isBlocked_whenIpExists_thenReturnTrue(){

        // given
        IpBlacklist existing = IpBlacklist.builder()
                .ipAddress("192.168.0.10")
                .build();
        // when
        when(blacklistRepository.findByIpAddress("192.168.0.10"))
                .thenReturn(Optional.of(existing));

        boolean result = blacklistService.isBlocked("192.168.0.10");

        // then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("블랙리스트 DB에 등록되어있지 않으면, false를 반환한다.")
    void isBlocked_whenIpNotExists_thenReturnFalse(){

        // when
        when(blacklistRepository.findByIpAddress("192.168.0.10"))
                .thenReturn(Optional.empty());

        // given
        boolean result = blacklistService.isBlocked("192.168.0.10");

        // then
        assertThat(result).isFalse();

    }
}



/*
테스트:
    1. 전체 블랙리스트 조회 시 Entity를 DTO로 변환한다.
    2. 새 IP 등록 성공 시 save 호출 후 true 반환
    3. 중복 IP 등록 시 save 하지 않고 false 반환
    4. 삭제 대상이 존재하면 deleteById 호출 후 true 반환
    5. 삭제 대상이 없으면 deleteById 호출하지 않고 false 반환
    6. isBlocked는 IP 존재 여부를 boolean으로 반환
*/




package com.example.security_log_system.service;

import com.example.security_log_system.dto.BlacklistSnapshotDto;
import com.example.security_log_system.repository.BlacklistRepository;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class BlacklistSnapshotServiceTest {

    @Mock
    private BlacklistRepository blacklistRepository;

    @InjectMocks
    private BlacklistSnapshotService blacklistSnapshotService;

    @Test
    @DisplayName("조회 순서와 중복이 달라도 동일한 IP 목록이면 같은 버전을 생성한다")
    void sameIpSetProducesSameVersion(){
        // when
        when(blacklistRepository.findAllIpAddresses())
                .thenReturn(List.of(
                        "203.0.113.20",
                        "198.51.100.10",
                        "203.0.113.20"
                ))
                .thenReturn(List.of(
                        "198.51.100.10",
                        "203.0.113.20"
                ));

        BlacklistSnapshotDto first =
                blacklistSnapshotService.getSnapshot();

        BlacklistSnapshotDto second =
                blacklistSnapshotService.getSnapshot();

        assertThat(first.ipAddresses())
                .containsExactly(
                        "198.51.100.10",
                        "203.0.113.20"
                );

        assertThat(first.version())
                .isEqualTo(second.version());
    }

    @Test
    @DisplayName("IP가 삭제되면 목록과 버전이 변경된다")
    void deletionChangesVersion(){
        //when
        when(blacklistRepository.findAllIpAddresses())
                .thenReturn(List.of(
                        "198.51.100.10",
                        "203.0.113.20"
                ))
                .thenReturn(List.of(
                        "198.51.100.10"
                ));
        BlacklistSnapshotDto before =
                blacklistSnapshotService.getSnapshot();
        BlacklistSnapshotDto after =
                blacklistSnapshotService.getSnapshot();

        assertThat(after.ipAddresses())
                .containsExactly("198.51.100.10");

        assertThat(after.version())
                .isNotEqualTo(before.version());
    }

    @Test
    @DisplayName("모든 IP가 삭제되면 새로운 버전의 빈 목록을 반환한다")
    void deletingAllIpsProducesEmptySnapshot(){
        when(blacklistRepository.findAllIpAddresses())
                .thenReturn(List.of("198.51.100.10"))
                .thenReturn(List.of());

        BlacklistSnapshotDto before =
                blacklistSnapshotService.getSnapshot();
        BlacklistSnapshotDto after =
                blacklistSnapshotService.getSnapshot();

        assertThat(after.ipAddresses()).isEmpty();

        assertThat(after.version())
                .matches("[0-9a-f]{64}")
                .isNotEqualTo(before.version());
    }

    @Test
    @DisplayName("DB 조회 실패를 빈 차단 목록으로 변환하지 않는다")
    void databaseFailureIsPropagated(){
       IllegalStateException failure =
               new IllegalStateException("DB unavailable");

       when(blacklistRepository.findAllIpAddresses())
               .thenThrow(failure);

       assertThatThrownBy(
               () -> blacklistSnapshotService.getSnapshot()
       ).isSameAs(failure);
    }

}

package com.example.security_log_system.service;

import com.example.security_log_system.dto.WafDetectionEventDto;
import com.example.security_log_system.repository.WafDetectionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class WafDetectionServiceTest {

    @Mock
    private WafDetectionRepository repository;

    @Mock
    private WafDetectionWriter writer;

    private WafDetectionService service;
    private WafDetectionEventDto event;

    @BeforeEach
    void setUp() throws Exception {
        service = new WafDetectionService(repository, writer);

        // 이 테스트에서는 Consumer 검증 이후의 중복 처리만 확인한다.
        event = new ObjectMapper().readValue(
                """
                {"request_id": "waf-test-001"}
                """,
                WafDetectionEventDto.class
        );
    }

    @Test
    @DisplayName("처음 수신한 요청이면 저장 담당 코드를 호출한다")
    void newRequest_isSaved() {
        when(repository.existsByRequestId("waf-test-001"))
                .thenReturn(false);

        service.handle(event);

        verify(writer).saveNewDetection(event);
    }

    @Test
    @DisplayName("이미 저장된 요청이면 다시 저장하지 않는다")
    void existingRequest_isSkipped() {
        when(repository.existsByRequestId("waf-test-001"))
                .thenReturn(true);

        service.handle(event);

        verifyNoInteractions(writer);
    }

    @Test
    @DisplayName("동시 저장 충돌 후 같은 요청이 존재하면 중복으로 처리한다")
    void concurrentDuplicate_isSkipped() {
        when(repository.existsByRequestId("waf-test-001"))
                .thenReturn(false, true);

        doThrow(new DataIntegrityViolationException("Duplicate"))
                .when(writer)
                .saveNewDetection(event);

        assertThatCode(() -> service.handle(event))
                .doesNotThrowAnyException();

        verify(writer).saveNewDetection(event);
    }

    @Test
    @DisplayName("무결성 오류 후 요청이 저장되지 않았다면 예외를 전파한다")
    void otherIntegrityFailure_isPropagated() {
        when(repository.existsByRequestId("waf-test-001"))
                .thenReturn(false, false);

        DataIntegrityViolationException failure =
                new DataIntegrityViolationException("Other constraint");

        doThrow(failure)
                .when(writer)
                .saveNewDetection(event);

        assertThatThrownBy(() -> service.handle(event))
                .isSameAs(failure);
    }

    @Test
    @DisplayName("일반 저장 실패는 재시도를 위해 호출자에게 전달한다")
    void storageFailure_isPropagated() {
        when(repository.existsByRequestId("waf-test-001"))
                .thenReturn(false);

        RuntimeException failure =
                new RuntimeException("Database unavailable");

        doThrow(failure)
                .when(writer)
                .saveNewDetection(event);

        assertThatThrownBy(() -> service.handle(event))
                .isSameAs(failure);
    }
}
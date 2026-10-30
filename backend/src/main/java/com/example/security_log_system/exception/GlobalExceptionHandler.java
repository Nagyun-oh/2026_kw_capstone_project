package com.example.security_log_system.exception;

import com.example.security_log_system.dto.ErrorResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

// @RestControllerAdvice:
// 모든 REST Controller에서 발생한 예외를 감시하고 처리하는 전역 예외 처리 클래스
@RestControllerAdvice
public class GlobalExceptionHandler {

    // @RequestBody @Valid DTO 검증 실패
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDto> handleValidation(
            MethodArgumentNotValidException exception
    ) {
        Map<String, String> errors = new LinkedHashMap<>();

        exception.getBindingResult().getFieldErrors()
                .forEach(error ->
                        errors.put(error.getField(),error.getDefaultMessage()));

        ErrorResponseDto response = new ErrorResponseDto(
                HttpStatus.BAD_REQUEST.value(),
                "Request validation failed.",
                errors,
                LocalDateTime.now()
        );

        return ResponseEntity.badRequest().body(response);

    }


    // @RequestParam, @PathVariable 검증 실패
    @ExceptionHandler(HandlerMethodValidationException.class)
    public ResponseEntity<ErrorResponseDto> handleMethodValidation(
            HandlerMethodValidationException exception
    ) {
        Map<String, String> errors = new LinkedHashMap<>();

        exception.getParameterValidationResults()
                .forEach(result -> {
                    String parameterName
                            = result.getMethodParameter().getParameterName();

                    result.getResolvableErrors()
                            .forEach(error -> errors.put(
                                    parameterName,
                                    error.getDefaultMessage()
                            ));
                });

        ErrorResponseDto response = new ErrorResponseDto(
                HttpStatus.BAD_REQUEST.value(),
                "Request validation failed.",
                errors,
                LocalDateTime.now()
        );

    return ResponseEntity.badRequest().body(response);

    }

}

/*
    HTTP 요청
    → JSON을 DTO로 변환
    → @Valid 검증
    → 검증 실패
    → MethodArgumentNotValidException 자동 발생
    → Spring이 @ExceptionHandler 검색
    → GlobalExceptionHandler.handleValidation() 자동 호출
    → ErrorResponse 생성
    → 400 Bad Request 반환

    @Valid가 예외를 발생시키고,
    @RestControllerAdvice와 @ExceptionHandler가 해당 예외를 찾아 자동으로 처리한다
* */

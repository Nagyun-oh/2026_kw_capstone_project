package com.example.security_log_system.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.*;

// 검증 규칙을 선언하는 사용자 정의 어노테이션

@Documented
@Constraint(validatedBy = IpAddressValidator.class)
@Target({ElementType.FIELD,ElementType.PARAMETER})   // 이 어노테이션을 필드(변수)에만 사용할 수 있도록 제한함.
@Retention(RetentionPolicy.RUNTIME)                 // 프로그램 실행 중에도 어노테이션 정보가 유지됨.
public @interface ValidIpAddress {

    // 검증 실패 시 사용할 기본 오류 메시지
    String message() default "Invalid IPv4 or IPv6 address.";    // 검증 실패 시 사용할 기본 오류 메시지
    Class<?>[] groups() default{};                               // 상황별로 검증 규칙을 묶을 때 사용하는 표준 속성
    Class<? extends Payload>[] payload() default {};             // 검증 오류에 추가 메타데이터를 넣을 때 사용하는 표준 속성
}

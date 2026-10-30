package com.example.security_log_system.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.net.Inet6Address;
import java.net.InetAddress;

// ValidIpAddress 어노테이션이 붙은 String값을 검증하는 클래스
public class IpAddressValidator implements ConstraintValidator<ValidIpAddress,String> {

    // true  → 검증 성공
    // false → 검증 실패
    @Override
    public boolean isValid(String value, ConstraintValidatorContext context){

        // 빈 값 검증은 @NotBlank가 담당한다.
        if(value==null || value.isBlank()){
            return true;
        }

        // IPv6는 콜론을 사용함.
        if(value.contains(":")){
            return isValidIpv6(value);
        }

        // Ipv4는 점을 사용함.
        return isValidIpv4(value);
    }

    private boolean isValidIpv4(String value){

        // 기능: 점을 기준으로 IP를 분리
        // 문법 설명:
        // 정규식에서 .은 특별한 의미가 있으므로 \\.로 작성한다.
        // 두 번째 인자 -1은 비어 있는 마지막 항목도 유지한다.
        String[] parts = value.split("\\.", -1);

        // Ipv4는 숫자 영역이 4개여야 한다.
        if (parts.length != 4) {
            return false;
        }

        // 각 영역 검사
        for (String part : parts) {

            // 빈 영역이거나 숫자가 아닌 문자가 있으면 실패
            if (part.isEmpty() || !part.chars().allMatch(Character::isDigit)) {
                return false;
            }

            try {
                // IPv4의 각 영역은 0 ~ 255 범위여야한다.
                int number = Integer.parseInt(part);
                if (number < 0 || number > 255) {
                    return false;
                }
            } catch (NumberFormatException exception) {
                return false;
            }
        }
        return true;
    }

    private boolean isValidIpv6(String value) {

        // IPv6에 사용할 수 있는 문자만 허용한다.
        if (!value.matches("[0-9a-fA-F:.]+")) {
            return false;
        }

        // Java 표준 IP 파싱
        // 파싱 결과가 실제 IPv6 타입인지 확인한다.
        try {
            InetAddress address = InetAddress.getByName(value);
            return address instanceof Inet6Address;
        } catch (Exception exception) {
            return false;
        }
    }
}

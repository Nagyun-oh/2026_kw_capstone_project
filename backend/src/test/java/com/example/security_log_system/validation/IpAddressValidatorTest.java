package com.example.security_log_system.validation;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

public class IpAddressValidatorTest {

    private final IpAddressValidator validator = new IpAddressValidator();

    @ParameterizedTest
    @ValueSource(strings = {
            "127.0.0.1",
            "192.168.0.10",
            "255.255.255.255",
            "2001:db8::1",
            "::1",
            "fe80::1234:abcd"
    })
    @DisplayName("IP 검증기 테스트: 유효한 IP주소(IPv4,Ipv6)를 받으면 true를 반환한다")
    void validIpAddress_thenReturnTrue(String ipAddress){
        assertThat(validator.isValid(ipAddress,null)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "256.1.1.1",
            "192.168.0",
            "192.168.0.1.5",
            "192.168.a.1",
            "2001:db8:::1",
            "not-an-ip",
            "example.com"
    })
    @DisplayName("IP 검증기 테스트: 유효하지 않은 IP주소를 받으면 false를 반환한다.")
    void invalidIpAddress_thenReturnFalse(String ipAddress) {
        assertThat(validator.isValid(ipAddress,null)).isFalse();
    }

}

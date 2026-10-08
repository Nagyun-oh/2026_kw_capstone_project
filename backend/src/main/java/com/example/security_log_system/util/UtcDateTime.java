package com.example.security_log_system.util;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

public final class UtcDateTime {

    private UtcDateTime(){
    }

    // DB에는 시간대 없는 LocalDateTime을 UTC 기준으로 저장
    public static LocalDateTime now(){
        return LocalDateTime.now(ZoneOffset.UTC);
    }

    // UTC 기준으로 저장된 DB 값에 UTC 오프셋을 붙여 응답
    public static OffsetDateTime toOffset(LocalDateTime value){
        return value == null
                ? null
                : value.atOffset(ZoneOffset.UTC);
    }
}

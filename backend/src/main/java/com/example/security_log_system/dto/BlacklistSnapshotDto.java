package com.example.security_log_system.dto;

import java.util.List;

public record BlacklistSnapshotDto(
        String version,
        List<String> ipAddresses
) {
    public BlacklistSnapshotDto{
        //  List.copyOf : 생성한 스냅샷의 목록이 나중에 다른 코드에서 변경되지 않도록 보호
        ipAddresses = List.copyOf(ipAddresses);
    }
}

package com.example.security_log_system.service;

import com.example.security_log_system.dto.BlacklistSnapshotDto;
import com.example.security_log_system.repository.BlacklistRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

@Service
@RequiredArgsConstructor
public class BlacklistSnapshotService {

    private final BlacklistRepository blacklistRepository;

    @Transactional(readOnly = true)
    public BlacklistSnapshotDto getSnapshot(){
        List<String> ipAddresses = blacklistRepository
                .findAllIpAddresses()
                .stream()   // 목록을 가공할 스트림 생성
                .distinct() // 중복 문자열 제거
                .sorted()   // 오름차순 정렬
                .toList();

        String version = calculateVersion(ipAddresses);

        return new BlacklistSnapshotDto(
                version,
                ipAddresses
        );
    }

    private String calculateVersion(List<String> ipAddresses){
        String content = String.join("\n",ipAddresses);

        try{
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(
                    content.getBytes(StandardCharsets.UTF_8)
            );

            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception){
            throw new IllegalStateException(
                    "SHA-256 is unavailable",
                    exception
            );
        }
    }
}
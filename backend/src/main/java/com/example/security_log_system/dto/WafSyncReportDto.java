package com.example.security_log_system.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

/* 보고 요청 DTO */
public record WafSyncReportDto(
        @NotBlank
        @Pattern(regexp = "[a-z0-9._-]{1,64}")
        String wafId,

        @Pattern(regexp = "[0-9a-f]{64}")
        String attemptedVersion,

        @Pattern(regexp = "[0-9a-f]{64}")
        String appliedVersion,

        @NotNull
        SyncResult lastSyncResult,

        List<@NotNull @Valid ExcludedIp> excludedIps,

        @Valid SyncError error

) {

    public enum SyncResult{
        SUCCESS,
        FAILURE,
        UNKNOWN
    }

    public enum ExclusionReason{
        LOOPBACK,
        UNSPECIFIED_ADDRESS,
        GATEWAY,
        TRUSTED_PROXY,
        CONFIGURED_EXCLUSION,
        INVALID_FORMAT
    }

    public record ExcludedIp(@NotNull String ip, @NotNull ExclusionReason reason){
    }

    public record SyncError(@NotBlank @Size(max =100)String code, @NotBlank @Size(max = 300)String message){
    }

    @JsonIgnore
    @AssertTrue(message = "WAF 보고 필드의 상태 조합이 올바르지 않습니다.")
    public boolean isConsistent(){
        if(lastSyncResult == null){
            return false;
        }

        // 적용 version과 제외 목록의 확인 여부는 함께 움직한다.
        if((appliedVersion == null) != (excludedIps == null) ){
            return false;
        }

        return switch(lastSyncResult){
            case SUCCESS ->
                attemptedVersion != null
                        && attemptedVersion.equals(appliedVersion)
                        && error == null;

            case FAILURE ->
                error != null;

            case UNKNOWN ->
                appliedVersion == null
                        && excludedIps == null;

        };
    }
}

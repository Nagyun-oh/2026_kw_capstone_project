package com.example.security_log_system.controller;


import com.example.security_log_system.dto.LogResponseDto;
import com.example.security_log_system.dto.LogSearchCondition;
import com.example.security_log_system.service.LogService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
// 기능 : 전체 로그 조회 API

@Tag(name = "Log API", description = "전체 로그 조회 및 관리 API")
@RestController
@RequestMapping("/api/v1/logs")
@RequiredArgsConstructor
public class LogController {

    private final LogService logService;

    // GET
    @GetMapping
    public ResponseEntity<Page<LogResponseDto>> getLogs(
            @Valid @ModelAttribute LogSearchCondition condition,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ){
        PageRequest pageable = PageRequest.of(
                page,
                size,
                Sort.by(Sort.Direction.DESC,"createdAt")
        );
        return ResponseEntity.ok(logService.getLogs(condition,pageable));
    }

    // ID로 원본 로그 상세 조회
    @GetMapping("/{id}")
    public ResponseEntity<LogResponseDto> getLogById(@PathVariable Long id){
        return ResponseEntity.of(logService.getLogById(id));
    }

}
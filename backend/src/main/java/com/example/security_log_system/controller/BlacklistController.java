package com.example.security_log_system.controller;

import com.example.security_log_system.dto.BlacklistRequestDto;
import com.example.security_log_system.dto.BlacklistResponseDto;
import com.example.security_log_system.dto.BlacklistSearchCondition;
import com.example.security_log_system.service.BlacklistService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Tag(name = "BlackList API", description = "차단 데이터 조회 및 관리 API")
@Validated
@RestController
@RequestMapping("/api/v1/blacklist")
@RequiredArgsConstructor
public class BlacklistController {

    private final BlacklistService blacklistService;

    // GET (createdAt 기준 최신순으로 20개씩 반환)
    @GetMapping
    public ResponseEntity<Page<BlacklistResponseDto>>getBlackLists(
            @Valid @ModelAttribute BlacklistSearchCondition condition,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ){
        PageRequest pageable = PageRequest.of(
                page,
                size,
                Sort.by(Sort.Direction.DESC,"createdAt")
        );

        return ResponseEntity.ok(blacklistService.getBlacklists(condition,pageable));
    }

    // POST
    @PostMapping
    public ResponseEntity<String> addBlackList(@Valid @RequestBody BlacklistRequestDto request){

        boolean added = blacklistService.addToBlacklist(
                request.getIpAddress(),
                request.getReason(),
                request.getDangerLevel()
        );

        if(!added){
            return ResponseEntity.badRequest()
                    .body("IP is already blacklisted.");
        }

        return ResponseEntity.ok(
                "IP was added to the blacklist."
        );
    }

    // DELETE
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteBlacklist(@PathVariable Long id){
        //존재하지 않음 → 404 Not Found
        if(!blacklistService.deleteBlacklist(id)){
            return ResponseEntity.notFound().build();
        }
        // 삭제 성공 → 204 No Content
        return ResponseEntity.noContent().build();
    }

}


package com.example.security_log_system.service;

import com.example.security_log_system.dto.AiRequestDto;
import com.example.security_log_system.dto.LogResponseDto;
import com.example.security_log_system.dto.LogSearchCondition;
import com.example.security_log_system.entity.LogEntry;
import com.example.security_log_system.kafka.AiRequestProducer;
import com.example.security_log_system.repository.LogRepository;
import com.example.security_log_system.repository.LogSpecification;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import com.example.security_log_system.util.UtcDateTime;

@Slf4j
@Transactional
@Service
@RequiredArgsConstructor
public class LogService {

    private final LogRepository logRepository;
    private final BlacklistService blacklistService;
    private final AiRequestProducer aiRequestProducer;

    // GET
    @Transactional(readOnly = true)
    public Page<LogResponseDto> getLogs(LogSearchCondition condition, Pageable pageable){
        return logRepository
                .findAll(LogSpecification.search(condition),pageable)
                .map(LogResponseDto::from);
    }

    // ID로 원본 로그 하나 조회
    @Transactional(readOnly = true)
    public Optional<LogResponseDto> getLogById(Long id){
        return logRepository.findById(id)
                .map(LogResponseDto::from);
    }

    // JSON 파싱을 위한 객체 추가
    private final ObjectMapper objectMapper;

    public void processRawLog(String kafkaMessage) {
        try{
            JsonNode jsonNode = objectMapper.readTree(kafkaMessage);

            // {"log" : "..."} 테스트
            if(jsonNode.has("log")){
                processNginxLog(jsonNode.get("log").asText());
                return;
            }

            // 실제 WAF Fluent Bit JSON 테스트
            if(jsonNode.has("remote_addr") && jsonNode.has("method") && jsonNode.has("path")){
                processWafAccessJson(jsonNode);
                return ;
            }

            // dev_tools 테스트
            if(jsonNode.has("method") && jsonNode.has("url_path")) {
                processAiInputJson(jsonNode);
                return;
            }
            log.warn("Unsupported Kafka message format. length={}",kafkaMessage.length());
        } catch(JsonProcessingException exception) {
            // 로그  파싱 실패 시 런타임 예외로 던져서 전체 트랙잭션 롤백 유도
            throw new RuntimeException("Kafka message parsing error: ",exception);
        }
    }

    private void processNginxLog(String message) {

        // 2. 줄바꿈 기호 (\r)만 들어오거나 빈 값인 경우 처리 중단
        if (message == null ||message.isBlank()) {
            return;
        }

        // 정규표현식: Nginx 기본 로그 형식을 분석합니다.
        // 예시 로그 : 127.0.0.1 - - [14/Mar/2026] "GET /admin HTTP/1.1" 403
        String regex = "^(\\S+) - - \\[(.*?)\\] \"(\\S+) (\\S+) .*?\" (\\d+)";
        Pattern pattern = Pattern.compile(regex);   // 미리 정의한 regex(정규표현식 문자열)을 컴퓨터가 해석하기 쉬운 형태인 Pattern 객체로 컴파일 (성능개선 부분)
        Matcher matcher = pattern.matcher(message); // 위에서 만든 pattern과 message(로그)를 비교하여 Matcher 객체 생성 (대조할 수 있는 상태 완성)

        // 정규 표현식 패턴이 맞는지 확인
        if (matcher.find()) {
            // 각 그룹별로 데이터를 추출합니다.
            String ip = matcher.group(1);      // 127.0.0.1
            String method = matcher.group(3);   // GET
            String url = matcher.group(4);      // admin
            int status = Integer.parseInt(matcher.group(5));    //403

            if (blacklistService.isBlocked(ip)) {
                return;
            }

            // 1. 로그 저장
            LogEntry entry = logRepository.save(LogEntry.builder()
                    .ipAddress(ip)
                    .requestMethod(method)
                    .requestUrl(url)
                    .statusCode(status)
                    .rawLog(message)
                    .createdAt(LocalDateTime.now())
                    .build());

            //  AI 서버로 분석 요청
            AiRequestDto aiRequest = AiRequestDto.builder()
                    .logId(entry.getId())
                    .method(method)
                    .urlPath(url)
                    .queryParams("")        // Nginx 로그엔 없으면 빈 값
                    .bodyContent("")
                    .userAgent("")
                    .ipAddress(ip)
                    .timestamp(LocalDateTime.now().toString())
                    .build();

            aiRequestProducer.sendAnalysisRequest(aiRequest);
        }
    }


    private void processWafAccessJson(JsonNode jsonNode){
        String ipAddress = jsonNode.path("remote_addr").asText("0.0.0.0");
        String method = jsonNode.path("method").asText("");
        String fullPath = jsonNode.path("path").asText("/");
        int statusCode = jsonNode.path("status").asInt(0);
        String userAgent = jsonNode.path("http_user_agent").asText("");
        String bodyContent = jsonNode.path("request_body").asText("");

        String urlPath = fullPath;
        String queryParams = "";

        int queryIndex = fullPath.indexOf("?");
        if(queryIndex >= 0){
            urlPath = fullPath.substring(0,queryIndex);
            queryParams = fullPath.substring(queryIndex+1);
        }

        // 입력된 로그 DB에 저장
        LogEntry entry = logRepository.save(LogEntry.builder()
                .ipAddress(ipAddress)
                .requestMethod(method)
                .requestUrl(fullPath)
                .statusCode(statusCode)
                .rawLog(jsonNode.toString())
                .createdAt(UtcDateTime.now())
                .build());

        // AI 요청 DTO 생성
        AiRequestDto aiRequest = AiRequestDto.builder()
                .logId(entry.getId())
                .method(method)
                .urlPath(urlPath)
                .queryParams(queryParams)
                .bodyContent(bodyContent)
                .userAgent(userAgent)
                .ipAddress(ipAddress)
                .timestamp(LocalDateTime.now().toString())
                .build();

        aiRequestProducer.sendAnalysisRequest(aiRequest);
    }

    private void processAiInputJson(JsonNode jsonNode) {
        String method = jsonNode.path("method").asText();
        String urlPath = jsonNode.path("url_path").asText();
        String queryParams = jsonNode.path("query_params").asText("");
        String bodyContent = jsonNode.path("body_content").asText("");
        String userAgent = jsonNode.path("user_agent").asText("");
        String ipAddress = jsonNode.path("ip_address").asText("127.0.0.1");
        String timestamp = jsonNode.path("timestamp").asText(LocalDateTime.now().toString());

        String requestUrl = queryParams.isBlank()
                ? urlPath
                : urlPath + "?" + queryParams;

        LogEntry entry = logRepository.save(LogEntry.builder()
                .ipAddress(ipAddress)
                .requestMethod(method)
                .requestUrl(requestUrl)
                .statusCode(200)
                .rawLog(jsonNode.toString())
                .createdAt(LocalDateTime.now())
                .build());

        AiRequestDto aiRequest = AiRequestDto.builder()
                .logId(entry.getId())
                .method(method)
                .urlPath(urlPath)
                .queryParams(queryParams)
                .bodyContent(bodyContent)
                .userAgent(userAgent)
                .ipAddress(ipAddress)
                .timestamp(timestamp)
                .build();

        aiRequestProducer.sendAnalysisRequest(aiRequest);
    }
}
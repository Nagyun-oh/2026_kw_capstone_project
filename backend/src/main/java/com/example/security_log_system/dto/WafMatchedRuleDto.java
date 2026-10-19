package com.example.security_log_system.dto;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

// WAF 이벤트 안의 개별 탐지 규칙
@Getter
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class WafMatchedRuleDto {

    @NotBlank(message = "WAF rule ID is required.")
    private String id;

    // 아래 필드들은 없는 경우도 허용
    private String message;

    // WAF 원본 심각도, 화면의 MEDIUM/HIGH/CRITICAL 변환은 서비스에서 수행한다.
    private String severity;

    @JsonProperty("matched_variable")
    private String matchedVariable;

    private List<@NotBlank(message= "Attack type must not be blank") String> attackTypes = new ArrayList<>();

    @JsonProperty("attack_types")
    public void setAttackTypes(JsonNode value){
        if (value == null
                || value.isNull()
                || (value.isObject() && value.isEmpty())
        ) {
            attackTypes = new ArrayList<>();
            return;
        }

        if(!value.isArray()){
            throw new IllegalArgumentException("attack_types must be an array of strings");
        }

        List<String> parsedTypes = new ArrayList<>();

        for(JsonNode element : value){
            if(!element.isTextual()){
                throw new IllegalArgumentException("Each attack_types item must be a string.");
            }
            parsedTypes.add(element.textValue());
        }
        attackTypes = parsedTypes;
    }
}

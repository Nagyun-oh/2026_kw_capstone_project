package com.example.security_log_system.repository;


import com.example.security_log_system.dto.ThreatSearchCondition;
import com.example.security_log_system.entity.DetectedThreat;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;


@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ThreatSpecification {

    public static Specification<DetectedThreat> search(ThreatSearchCondition condition){

        return (root, query,builder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if(StringUtils.hasText(condition.getSource())){
                String threatType = switch (condition.getSource()){
                    case "AI" -> "AI Detection";
                    case "WAF" -> "WAF Detection";
                    default -> throw new IllegalArgumentException("Unsupported threat source.");
                };

                predicates.add(
                        builder.equal(root.get("threatType"),threatType)
                );
            }

            if(StringUtils.hasText(condition.getThreatType())){
                predicates.add(builder.like(
                        builder.lower(root.get("threatType")),
                        "%"+ condition.getThreatType().trim().toLowerCase()+"%"
                ));
            }

            if(StringUtils.hasText(condition.getSeverity())){
                predicates.add(builder.equal(
                        root.get("severity"),
                        condition.getSeverity().trim().toUpperCase()
                ));
            }

            return builder.and(predicates.toArray(Predicate[]::new));
        };
    }
}

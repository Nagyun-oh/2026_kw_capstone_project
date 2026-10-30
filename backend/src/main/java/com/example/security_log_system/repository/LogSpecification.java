package com.example.security_log_system.repository;


import com.example.security_log_system.dto.LogSearchCondition;
import com.example.security_log_system.entity.LogEntry;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import jakarta.persistence.criteria.Predicate;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class LogSpecification {

    public static Specification<LogEntry> search (LogSearchCondition condition){
        return (root,query,builder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if(condition.getLogId() !=null){
                predicates.add(builder.equal(
                        root.get("id"),
                        condition.getLogId()
                ));
            }

            if (StringUtils.hasText(condition.getIp())) {
                predicates.add(builder.equal(
                        root.get("ipAddress"),
                        condition.getIp().trim()
                ));
            }

            if (StringUtils.hasText(condition.getMethod())) {
                predicates.add(builder.equal(
                        root.get("requestMethod"),
                        condition.getMethod().trim().toUpperCase()
                ));
            }

            if(condition.getStatusCode()!=null){
                predicates.add(builder.equal(
                        root.get("statusCode"),
                        condition.getStatusCode()
                ));
            }

            return builder.and(
                    predicates.toArray(Predicate[]::new)
            );
        };
    }
}

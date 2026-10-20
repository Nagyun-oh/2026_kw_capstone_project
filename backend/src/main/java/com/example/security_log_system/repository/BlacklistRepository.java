package com.example.security_log_system.repository;


import com.example.security_log_system.entity.IpBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/* 차단된 IP들을 관리하는 용도입니다. */
@Repository
public interface BlacklistRepository
        extends JpaRepository<IpBlacklist,Long>,
        JpaSpecificationExecutor<IpBlacklist> {
    Optional<IpBlacklist> findByIpAddress(String ipAddress);

    @Query("""
        select a.ipAddress
        from IpBlacklist a
    """)
    List<String> findAllIpAddresses();
}